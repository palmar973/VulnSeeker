"""
Detección de servidores con respuesta *catch-all* (soft-404).

Muchos servidores no devuelven 404 ante una ruta inexistente, sino 200 con una
página genérica. Es el comportamiento por defecto de las SPA (Angular/React/Vue),
que sirven su index.html para cualquier ruta para que el enrutado ocurra en el
cliente. También lo hacen algunos front-ends, WAF y páginas de error a medida.

Para un escáner que infiere "el recurso existe" a partir de un código 200, esto
genera falsos positivos en masa (cree que .env, .git, backups, paneles admin…
existen, cuando el servidor simplemente responde 200 a todo).

Esta utilidad sondea rutas aleatorias garantizadamente inexistentes para aprender
la "firma" de esa página catch-all y permite descartar respuestas que coincidan
con ella. En servidores que sí devuelven 404 real (p. ej. DVWA), no se activa y el
comportamiento del escáner no cambia.
"""
import logging
import random
import string
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)


class CatchAllBaseline:
    """Aprende la firma de la página soft-404/catch-all de un servidor."""

    def __init__(self, base_url: str, headers: dict | None = None,
                 cookies: dict | None = None, samples: int = 2, timeout: float = 4.0) -> None:
        self.base_url = base_url
        self.is_catch_all = False
        self._lengths: list[int] = []

        normalized = base_url if base_url.endswith("/") else base_url + "/"
        try:
            for _ in range(samples):
                rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
                probe_url = urljoin(normalized, f"{rnd}.html")
                resp = requests.get(probe_url, headers=headers or {}, cookies=cookies or {},
                                    timeout=timeout, allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    self._lengths.append(len(resp.content))
                else:
                    # Una sola sonda con código != 200 basta para descartar catch-all.
                    self._lengths = []
                    break
            self.is_catch_all = len(self._lengths) == samples and samples > 0
            if self.is_catch_all:
                logger.info(f"🌀 Servidor catch-all detectado en {base_url} "
                            f"(rutas inexistentes devuelven 200, ~{self._lengths[0]} bytes). "
                            f"Se filtrarán falsos positivos por soft-404.")
        except requests.RequestException:
            self.is_catch_all = False

    def is_false_positive(self, response) -> bool:
        """True si la respuesta coincide con la página catch-all aprendida, es decir,
        su código 200 NO implica que el recurso realmente exista."""
        if not self.is_catch_all or response is None:
            return False
        if getattr(response, "status_code", None) != 200:
            return False
        try:
            length = len(response.content)
        except (TypeError, AttributeError):
            return False
        for base_len in self._lengths:
            tolerance = max(64, int(base_len * 0.05))
            if abs(length - base_len) <= tolerance:
                return True
        return False
