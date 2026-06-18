import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, parse_qsl
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Optional, Tuple
from core.scanner_types import PageElement
from core.config import GlobalConfig

logger = logging.getLogger(__name__)


def normalize_url_structure(url: str) -> str:
    """
    Normaliza una URL manteniendo solo su ruta base y las llaves (keys)
    de sus parámetros ordenadas alfabéticamente.
    Previene que el escáner trate la misma ruta como 'nueva' solo porque
    el valor del parámetro cambió.

    Ejemplo:
        /page?id=1&cat=5 → /page?cat=&id=
        /page?id=99&cat=3 → /page?cat=&id=  (misma estructura → se ignora)
    """
    parsed = urlparse(url)
    query_keys = sorted([key for key, _ in parse_qsl(parsed.query)])
    normalized_query = urlencode([(k, "") for k in query_keys])
    return parsed._replace(query=normalized_query, fragment="").geturl()


class WebCrawler:
    """
    Explorador estructural de la aplicación objetivo.
    No solo busca URLs, cataloga formularios y puntos de entrada de datos.

    Incluye tres mecanismos anti-explosión combinatoria:
    1. Normalización estructural de URLs (misma ruta + mismos params = 1 solo endpoint)
    2. Límite de profundidad (MAX_CRAWL_DEPTH) contra spider traps
    3. Límite de páginas (MAX_CRAWL_PAGES) como tope absoluto
    """

    def __init__(self, start_url: str, max_pages: int = 50, cookies: dict | None = None) -> None:
        # Guardo la base para no terminar escaneando todo internet por accidente.
        self.start_url: str = start_url
        self.base_domain: str = urlparse(start_url).netloc
        self.max_pages: int = max_pages
        self.max_depth: int = GlobalConfig.MAX_CRAWL_DEPTH
        self.cookies: dict = cookies or {}

        self.visited_urls: Set[str] = set()
        self.discovered_elements: List[PageElement] = []
        # Set de estructuras normalizadas ya vistas (previene explosión combinatoria)
        self._seen_structures: Set[str] = set()

    def start(self) -> List[PageElement]:
        """
        Orquesta la navegación recursiva con control de profundidad.
        Retorna la lista de elementos (links y formularios) para el arsenal.
        """
        logger.info(f"Iniciando fase de reconocimiento en: {self.start_url}")

        # Cola con tuplas (url, profundidad)
        queue: List[Tuple[str, int]] = [(self.start_url, 0)]

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)

            if current_url in self.visited_urls:
                continue

            # Control de profundidad: no seguir links más allá del límite
            if depth > self.max_depth:
                continue

            self.visited_urls.add(current_url)

            try:
                html_content = self._fetch_page(current_url)
                if not html_content:
                    continue

                new_links = self._parse_structure(current_url, html_content)

                for link in new_links:
                    if link not in self.visited_urls:
                        queue.append((link, depth + 1))

            except Exception as e:
                logger.error(f"Fallo en navegación sobre {current_url}: {e}")

        logger.info(f"Reconocimiento completo. {len(self.discovered_elements)} puntos de ataque mapeados "
                     f"({len(self._seen_structures)} estructuras únicas, "
                     f"{len(self.visited_urls)} páginas visitadas).")
        return self.discovered_elements

    def _fetch_page(self, url: str) -> Optional[str]:
        """
        Descargador con modales. Intenta obtener el HTML de la página.
        """
        headers: Dict[str, str] = {'User-Agent': GlobalConfig.USER_AGENT}
        try:
            response = requests.get(url, headers=headers, cookies=self.cookies,
                                    timeout=GlobalConfig.REQUEST_TIMEOUT)
            if "text/html" in response.headers.get("Content-Type", ""):
                return response.text
        except requests.RequestException:
            pass
        return None

    def _is_new_structure(self, url: str) -> bool:
        """
        Verifica si la estructura de la URL (ruta + nombres de parámetros)
        es nueva. Si /page?id=1 ya se vio, /page?id=99 se ignora.
        """
        structure = normalize_url_structure(url)
        if structure in self._seen_structures:
            return False
        self._seen_structures.add(structure)
        return True

    def _parse_structure(self, url: str, html: str) -> List[str]:
        """
        Analizo el HTML buscando puertas de entrada (links y forms).
        Solo agrega endpoints con estructuras nuevas (normalización anti-explosión).
        """
        soup = BeautifulSoup(html, "html.parser")
        found_links: List[str] = []

        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag["href"]).split("#")[0]
            if self._is_in_scope(full_url):
                # Solo agregar como endpoint si la estructura es nueva
                if self._is_new_structure(full_url):
                    parsed_query = urlparse(full_url).query
                    params = {k: v[0] for k, v in parse_qs(parsed_query).items()}

                    self.discovered_elements.append(PageElement(
                        url=full_url,
                        params=params,
                        is_form=False
                    ))

                # Siempre seguir el link para descubrir más páginas
                # (pero con control de visited_urls y profundidad)
                found_links.append(full_url)

        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").upper()
            form_url = urljoin(url, action)

            if self._is_in_scope(form_url):
                inputs: Dict[str, str] = {}
                for input_tag in form.find_all(["input", "textarea"]):
                    name = input_tag.get("name")
                    if name:
                        inputs[name] = input_tag.get("value", "")

                # Normalizar formulario: ruta + nombres de campos
                form_structure = f"{urlparse(form_url).path}::{'|'.join(sorted(inputs.keys()))}"
                if form_structure not in self._seen_structures:
                    self._seen_structures.add(form_structure)
                    self.discovered_elements.append(PageElement(
                        url=form_url,
                        method=method,
                        params=inputs,
                        is_form=True
                    ))

        return found_links

    def _is_in_scope(self, url: str) -> bool:
        """
        Filtro de seguridad para no terminar atacando dominios externos.
        """
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain and parsed.scheme in ["http", "https"]