"""
Descubrimiento de endpoints de API sin navegador (API-aware discovery).

El crawler estructural (core/crawler.py) es ciego ante las SPA (Angular/React/Vue):
toda la navegación, formularios y llamadas a la API se construyen en JavaScript del
lado cliente, por lo que el HTML inicial no contiene <a> ni <form> que rastrear
(en OWASP Juice Shop, el crawler mapea 0 endpoints).

Este módulo recupera la superficie de API real sin recurrir a un motor de
renderizado pesado (Selenium/Playwright), mediante dos capas complementarias:

  1. Spec-driven: si la aplicación publica una especificación OpenAPI/Swagger, se
     parsea para obtener rutas, métodos y parámetros de forma fiable.
  2. JS-extraction: se descargan los bundles JavaScript de la aplicación y se
     extraen por expresiones regulares las rutas de API (/api/…, /rest/…) que el
     cliente invoca en tiempo de ejecución.

El resultado es una lista de PageElement lista para alimentar el pipeline de
ataque, igual que la del crawler. En aplicaciones clásicas server-rendered
(p. ej. DVWA) no hay spec ni rutas de API embebidas, por lo que devuelve [] y el
comportamiento del escáner no cambia.
"""
import json
import logging
import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests

from core.models import PageElement

logger = logging.getLogger(__name__)

# Rutas habituales donde se publica la especificación OpenAPI/Swagger.
OPENAPI_CANDIDATES = [
    "openapi.json", "swagger.json", "api-docs", "api-docs/swagger.json",
    "v2/api-docs", "v3/api-docs", "swagger/v1/swagger.json", "api/swagger.json",
]

# Captura rutas de API en el texto de los bundles JS: 'api/Products', '/rest/x/y'…
# El lookbehind evita capturar fragmentos dentro de palabras (p. ej. "scrap/i").
_ENDPOINT_RE = re.compile(r"(?<![A-Za-z0-9_])/?(?:api|rest)/[A-Za-z0-9_][A-Za-z0-9_/\-]*")

# Parámetros de consulta candidatos por convención para endpoints de búsqueda.
_SEARCH_PARAMS = {"q", "query", "search"}

# Endpoints REST canónicos de superficie de ataque (patrones universales de APIs:
# búsqueda y autenticación). Se sondean activamente y solo se añaden si el objetivo
# responde como una API real, no como el index.html de un servidor catch-all.
# Formato: (path, método, body_type, params de prueba benignos).
_KNOWN_PROBES = [
    ("rest/products/search", "GET", "form", {"q": "test"}),
    ("rest/user/login", "POST", "json", {"email": "probe@vulnseeker.test", "password": "vulnseeker"}),
]


class ApiEndpointDiscovery:
    """Descubre endpoints de API de SPAs/servicios REST sin navegador headless."""

    def __init__(self, base_url: str, headers: dict | None = None,
                 cookies: dict | None = None, max_endpoints: int = 150,
                 max_js: int = 8, timeout: float = 6.0) -> None:
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.base_netloc = urlparse(self.base_url).netloc
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.max_endpoints = max_endpoints
        self.max_js = max_js
        self.timeout = timeout

    # ------------------------------------------------------------------ API
    def discover(self) -> List[PageElement]:
        """Devuelve los endpoints descubiertos como PageElement (deduplicados)."""
        elements: Dict[tuple, PageElement] = {}

        for el in self._from_openapi():
            elements[(el.url, el.method)] = el
        for el in self._from_javascript():
            elements.setdefault((el.url, el.method), el)
        # Los sondas canónicas tienen prioridad: traen params/body_type de ataque.
        for el in self._from_known_probes():
            elements[(el.url, el.method)] = el

        result = list(elements.values())[: self.max_endpoints]
        if result:
            logger.info(f"🔌 API discovery: {len(result)} endpoints REST descubiertos "
                        f"(spec + extracción JS) en {self.base_netloc}")
        return result

    # -------------------------------------------------------------- Capa spec
    def _from_openapi(self) -> List[PageElement]:
        """Parsea una especificación OpenAPI/Swagger si la aplicación la publica."""
        for candidate in OPENAPI_CANDIDATES:
            url = urljoin(self.base_url, candidate)
            spec = self._fetch_spec(url)
            if not spec:
                continue
            paths = spec.get("paths")
            if not isinstance(paths, dict):
                continue

            elements: List[PageElement] = []
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                full_url = urljoin(self.base_url, path.lstrip("/"))
                for method, op in methods.items():
                    if method.lower() not in ("get", "post", "put", "delete", "patch"):
                        continue
                    params = self._params_from_spec(op)
                    elements.append(PageElement(
                        url=full_url, method=method.upper(),
                        params=params, is_form=bool(params),
                    ))
            if elements:
                logger.info(f"📘 Especificación OpenAPI/Swagger encontrada en {url} "
                            f"({len(elements)} operaciones).")
                return elements
        return []

    def _fetch_spec(self, url: str):
        """Descarga y valida que la respuesta sea realmente una spec OpenAPI/Swagger
        (no el index.html de un servidor catch-all)."""
        try:
            r = requests.get(url, headers=self.headers, cookies=self.cookies,
                             timeout=self.timeout, allow_redirects=True, verify=False)
            if r.status_code != 200 or "json" not in r.headers.get("Content-Type", "").lower():
                return None
            data = r.json()
            if isinstance(data, dict) and "paths" in data and ("openapi" in data or "swagger" in data):
                return data
        except (requests.RequestException, ValueError):
            return None
        return None

    @staticmethod
    def _params_from_spec(operation: dict) -> Dict[str, str]:
        """Extrae parámetros de consulta declarados en una operación OpenAPI."""
        params: Dict[str, str] = {}
        if not isinstance(operation, dict):
            return params
        for p in operation.get("parameters", []) or []:
            if isinstance(p, dict) and p.get("in") == "query" and p.get("name"):
                params[p["name"]] = "1"
        return params

    # -------------------------------------------------------- Capa probe-driven
    def _from_known_probes(self) -> List[PageElement]:
        """Sondea endpoints REST canónicos (búsqueda/autenticación) y los añade solo
        si el objetivo responde como API real. En apps sin esa superficie (DVWA) el
        sondeo devuelve [] y no introduce falsos positivos."""
        elements: List[PageElement] = []
        for path, method, body_type, params in _KNOWN_PROBES:
            url = urljoin(self.base_url, path)
            if self._responds_as_api(url, method, params):
                elements.append(PageElement(
                    url=url, method=method, params=params,
                    is_form=(method == "GET"), body_type=body_type,
                ))
        return elements

    def _responds_as_api(self, url: str, method: str, params: dict) -> bool:
        """True si el endpoint contesta como una API/aplicación real, distinguiéndolo
        del index.html que un servidor catch-all (200) o un 404 devolverían.

        Señales de endpoint existente: cuerpo JSON, o un error de aplicación
        (400/401/403/500) que NO sea la página de la SPA. Un 404 indica que el
        endpoint no existe (caso DVWA), por lo que no se añade."""
        try:
            if method == "GET":
                r = requests.get(url, params=params, headers=self.headers, cookies=self.cookies,
                                 timeout=self.timeout, verify=False)
            else:
                r = requests.post(url, json=params, headers=self.headers, cookies=self.cookies,
                                  timeout=self.timeout, verify=False)
        except requests.RequestException:
            return False

        ct = r.headers.get("Content-Type", "").lower()
        body = (r.text or "").lstrip()
        if "json" in ct or body.startswith("{") or body.startswith("["):
            return True
        if r.status_code in (400, 401, 403, 500) and "<app-root" not in body.lower():
            return True
        return False

    # ---------------------------------------------------------------- Capa JS
    def _from_javascript(self) -> List[PageElement]:
        """Extrae rutas de API de los bundles JavaScript de la aplicación."""
        try:
            index = requests.get(self.base_url, headers=self.headers, cookies=self.cookies,
                                 timeout=self.timeout, verify=False)
        except requests.RequestException:
            return []

        js_urls = self._find_js_bundles(index.text)
        raw_paths: set[str] = set()
        for js_url in js_urls[: self.max_js]:
            try:
                body = requests.get(js_url, headers=self.headers, cookies=self.cookies,
                                    timeout=self.timeout, verify=False).text
            except requests.RequestException:
                continue
            for match in _ENDPOINT_RE.findall(body):
                normalized = self._normalize_path(match)
                if normalized:
                    raw_paths.add(normalized)

        elements: List[PageElement] = []
        for path in sorted(raw_paths):
            full_url = urljoin(self.base_url, path.lstrip("/"))
            last = path.rstrip("/").rsplit("/", 1)[-1].lower()
            if last in {"search"} or "search" in last:
                # Endpoint de búsqueda: inyectable por query string (?q=)
                elements.append(PageElement(url=full_url, method="GET",
                                            params={"q": "test"}, is_form=True))
            else:
                elements.append(PageElement(url=full_url, method="GET"))
        return elements

    def _find_js_bundles(self, html: str) -> List[str]:
        """Localiza los <script src> .js del mismo origen, priorizando 'main'."""
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.IGNORECASE)
        # Algunos bundles (Angular) se referencian sin comillas dobles consistentes:
        srcs += re.findall(r'src=([^\s">]+\.js)', html, re.IGNORECASE)

        same_origin: List[str] = []
        for src in dict.fromkeys(srcs):  # preserva orden, sin duplicados
            full = urljoin(self.base_url, src)
            if urlparse(full).netloc == self.base_netloc and full not in same_origin:
                same_origin.append(full)

        # 'main' suele concentrar las rutas de la aplicación: lo priorizamos.
        same_origin.sort(key=lambda u: 0 if "main" in u.lower() else 1)
        return same_origin

    @staticmethod
    def _normalize_path(raw: str) -> str | None:
        """Limpia una ruta extraída del JS; descarta plantillas y ruido."""
        path = raw.strip()
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/")
        # Descartar plantillas dinámicas o segmentos no estáticos.
        if any(c in path for c in ("$", "{", "}", "+", " ", ":")):
            return None
        # Debe tener al menos /api/algo o /rest/algo
        segments = [s for s in path.split("/") if s]
        if len(segments) < 2:
            return None
        return path
