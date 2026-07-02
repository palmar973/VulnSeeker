"""
Modelo unificado de vectores de inyección para los módulos ofensivos de VulnSeeker.

Antes, cada módulo (SQLi, XSS, cmdi, LFI) resolvía por su cuenta la pregunta
"¿dónde inyecto y cómo envío la petición?", con una cobertura desigual:
SQLi cubría cuatro vectores, XSS tres, cmdi dos (y sólo el primer elemento) y
LFI uno. Esa inconsistencia era deuda de diseño. Este componente centraliza la
enumeración de puntos de inyección para que todos los módulos ataquen los mismos
vectores de forma homogénea; cada módulo sólo aporta sus payloads y su lógica de
detección, mientras que el "dónde" y el "cómo se envía" viven aquí, en un único
lugar:

  1. GET query  -> parámetros en la query string de ``target.url``.
  2. POST form  -> formularios ``method="post"`` (application/x-www-form-urlencoded).
  3. GET form   -> formularios ``method="get"`` (los params viajan a la query string).
  4. JSON body  -> endpoints REST que reciben ``application/json`` (SPAs / APIs).

Cada :class:`InjectionPoint` identifica un par (parámetro, vector) concreto y sabe
enviarse a sí mismo preservando el resto de parámetros del punto.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

# User-Agent de navegador para no ser filtrado por defensas triviales.
UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
DEFAULT_TIMEOUT = 6


@dataclass
class InjectionPoint:
    """Un punto de inyección concreto: un parámetro alcanzable por un vector.

    ``action_url`` es la URL de acción SIN la query mutada (para GET se reconstruye
    en :meth:`send`). ``base_params`` conserva todos los parámetros del punto para
    que al inyectar en uno no se pierda el contexto del resto (p. ej. el botón
    ``Submit`` de un formulario o el segundo campo de una API).
    """
    method: str                                   # "GET" | "POST"
    action_url: str                               # URL de acción sin query mutada
    param_name: str                               # parámetro a inyectar
    base_params: Dict[str, str] = field(default_factory=dict)
    body_type: str = "form"                       # "form" (urlencoded) | "json"
    report_url: str = ""                          # URL legible para el hallazgo

    def _mutated(self, value: str) -> Dict[str, str]:
        data = dict(self.base_params)
        data[self.param_name] = value
        return data

    def send(self, value, headers: Optional[Dict[str, str]] = None,
             timeout: float = DEFAULT_TIMEOUT, verify: bool = False,
             session=None) -> Optional[requests.Response]:
        """Inyecta ``value`` en este punto y devuelve la respuesta (``None`` si falla).

        Respeta el vector: JSON viaja como cuerpo ``application/json``, POST como
        formulario urlencoded y GET reconstruye la query string preservando el
        resto de parámetros.
        """
        http = session or requests
        hdrs = dict(headers) if headers else {"User-Agent": UA_BROWSER}
        data = self._mutated(str(value))
        try:
            if self.body_type == "json":
                hdrs.setdefault("Content-Type", "application/json")
                return http.post(self.action_url, json=data, headers=hdrs,
                                 timeout=timeout, verify=verify)
            if self.method == "POST":
                return http.post(self.action_url, data=data, headers=hdrs,
                                 timeout=timeout, verify=verify)
            parsed = urlparse(self.action_url)
            url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                              parsed.params, urlencode(data), parsed.fragment))
            return http.get(url, headers=hdrs, timeout=timeout, verify=verify)
        except requests.RequestException:
            return None


def collect_points(target, fallback_params: Optional[List[str]] = None) -> List[InjectionPoint]:
    """Enumera TODOS los puntos de inyección de un ``Target``, sin duplicados.

    Cubre los cuatro vectores que un DAST de caja negra puede alcanzar (GET query,
    POST form, GET form y JSON body). Si no se descubre ningún parámetro y se pasa
    ``fallback_params``, genera puntos GET sintéticos sobre la ruta de ``target.url``
    con nombres sospechosos habituales, replicando el comportamiento histórico de
    cmdi/LFI cuando el objetivo no expone un formulario.
    """
    points: List[InjectionPoint] = []
    seen = set()

    def add(point: InjectionPoint, key) -> None:
        if key not in seen:
            seen.add(key)
            points.append(point)

    # (1) GET query en target.url
    parsed = urlparse(target.url)
    query = parse_qs(parsed.query)
    if query:
        base = {k: v[0] for k, v in query.items()}
        action = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                             parsed.params, "", parsed.fragment))
        for name in query:
            add(InjectionPoint("GET", action, name, base, "form", target.url),
                ("GET", action, name, "form"))

    # (2-4) elementos descubiertos (formularios clásicos o endpoints REST)
    for el in getattr(target, "elements", None) or []:
        if not (el.is_form and el.params):
            continue
        method = el.method.upper()
        body_type = getattr(el, "body_type", "form")
        base = dict(el.params)
        for name in el.params:
            if body_type == "json":
                add(InjectionPoint("POST", el.url, name, base, "json", el.url),
                    ("POST", el.url, name, "json"))
            elif method == "POST":
                add(InjectionPoint("POST", el.url, name, base, "form", el.url),
                    ("POST", el.url, name, "form"))
            else:  # formulario GET: los params van a la query string
                add(InjectionPoint("GET", el.url, name, base, "form", el.url),
                    ("GET", el.url, name, "form"))

    # Fallback: nada descubierto -> nombres sospechosos sobre la ruta base
    if not points and fallback_params:
        action = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                             parsed.params, "", parsed.fragment))
        for name in fallback_params:
            add(InjectionPoint("GET", action, name, {name: ""}, "form", target.url),
                ("GET", action, name, "form"))

    return points
