import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Optional
from core.scanner_types import PageElement
from core.config import GlobalConfig

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Explorador estructural de la aplicación objetivo.
    No solo busca URLs, cataloga formularios y puntos de entrada de datos.
    """

    def __init__(self, start_url: str, max_pages: int = 50, cookies: dict | None = None) -> None:
        # Guardo la base para no terminar escaneando todo internet por accidente.
        self.start_url: str = start_url
        self.base_domain: str = urlparse(start_url).netloc
        self.max_pages: int = max_pages
        self.cookies: dict = cookies or {}

        self.visited_urls: Set[str] = set()
        self.discovered_elements: List[PageElement] = []

    def start(self) -> List[PageElement]:
        """
        Orquesta la navegación recursiva.
        Retorna la lista de elementos (links y formularios) para el arsenal.
        """
        logger.info(f"Iniciando fase de reconocimiento en: {self.start_url}")

        queue: List[str] = [self.start_url]

        while queue and len(self.visited_urls) < self.max_pages:
            current_url: str = queue.pop(0)

            if current_url in self.visited_urls:
                continue

            self.visited_urls.add(current_url)

            try:
                html_content = self._fetch_page(current_url)
                if not html_content:
                    continue

                new_links = self._parse_structure(current_url, html_content)

                for link in new_links:
                    if link not in self.visited_urls and link not in queue:
                        queue.append(link)

            except Exception as e:
                logger.error(f"Fallo en navegación sobre {current_url}: {e}")

        logger.info(f"Reconocimiento completo. {len(self.discovered_elements)} puntos de ataque mapeados.")
        return self.discovered_elements

    def _fetch_page(self, url: str) -> Optional[str]:
        """
        Descargador con modales. Intenta obtener el HTML de la página.
        """
        headers: Dict[str, str] = {'User-Agent': GlobalConfig.USER_AGENT}
        try:
            response = requests.get(url, headers=headers, cookies=self.cookies, timeout=5)
            if "text/html" in response.headers.get("Content-Type", ""):
                return response.text
        except requests.RequestException:
            pass
        return None

    def _parse_structure(self, url: str, html: str) -> List[str]:
        """
        Analizo el HTML buscando puertas de entrada (links y forms).
        """
        soup = BeautifulSoup(html, "html.parser")
        found_links: List[str] = []

        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag["href"]).split("#")[0]
            if self._is_in_scope(full_url):
                parsed_query = urlparse(full_url).query
                params = {k: v[0] for k, v in parse_qs(parsed_query).items()}

                self.discovered_elements.append(PageElement(
                    url=full_url,
                    params=params,
                    is_form=False
                ))
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