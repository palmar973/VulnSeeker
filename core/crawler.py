import logging
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Configuro el logger para este módulo específico.
logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Responsable de mapear la aplicación web objetivo.
    Utiliza un enfoque de descubrimiento recursivo (BFS) para encontrar
    enlaces internos y construir el mapa de ataque.
    """

    def __init__(self, start_url: str, max_pages: int = 50) -> None:
        # Guardo la URL inicial para definir el alcance (scope) del escaneo.
        self.start_url: str = start_url

        # Defino el dominio base. Si empiezo en example.com, no quiero terminar atacando facebook.com
        # urlparse me ayuda a extraer 'example.com' limpiamente.
        self.base_domain: str = urlparse(start_url).netloc

        # Limito la cantidad de páginas para evitar que la tesis se convierta en un escáner infinito.
        self.max_pages: int = max_pages

        # Uso un set (conjunto) para las URLs visitadas porque la búsqueda es O(1).
        # Si usara una lista, el rendimiento caería drásticamente con muchas URLs.
        self.visited_urls: set[str] = set()

        # Esta lista mantendrá las URLs únicas que descubra para devolverlas al Engine.
        self.found_urls: list[str] = []

    def start(self) -> list[str]:
        """
        Inicia el proceso de crawling.
        Devuelve una lista de URLs únicas encontradas dentro del alcance.
        """
        logger.info(f"Iniciando Crawler en: {self.start_url} (Scope: {self.base_domain})")

        # La cola de trabajo. Empiezo con la URL semilla.
        queue: list[str] = [self.start_url]

        while queue and len(self.visited_urls) < self.max_pages:
            # Saco la siguiente URL de la pila (FIFO).
            current_url: str = queue.pop(0)

            if current_url in self.visited_urls:
                continue

            # Marco como visitada antes de procesar para evitar condiciones de carrera lógicas.
            self.visited_urls.add(current_url)
            self.found_urls.append(current_url)

            # Intento extraer enlaces de esta página.
            try:
                new_links: list[str] = self._extract_links_from(current_url)

                # Añado los nuevos enlaces a la cola si no los he visto antes.
                for link in new_links:
                    if link not in self.visited_urls and link not in queue:
                        queue.append(link)

            except Exception as e:
                # Si una página falla (404, 500, timeout), lo registro y sigo.
                # El show debe continuar.
                logger.error(f"Error al procesar {current_url}: {e}")

        logger.info(f"Crawling finalizado. Se mapearon {len(self.found_urls)} recursos.")
        return self.found_urls

    def _extract_links_from(self, url: str) -> list[str]:
        """
        Método auxiliar privado. Descarga el HTML y extrae los hrefs.
        """
        logger.debug(f"Crawling: {url}")

        # Simulo ser un navegador real para evitar bloqueos simples.
        headers: dict[str, str] = {
            'User-Agent': 'VulnSeeker-Academic-Scanner/1.0'
        }

        # Hago la petición HTTP. Configuro un timeout para no quedarme colgado eternamente.
        response = requests.get(url, headers=headers, timeout=5)

        # Si no es HTML (ej: es una imagen o PDF), no intento parsearlo.
        if "text/html" not in response.headers.get("Content-Type", ""):
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        extracted_links: list[str] = []

        # Busco todas las etiquetas <a> con atributo href.
        for tag in soup.find_all("a", href=True):
            href: str = tag["href"]

            # Normalizo la URL. Esto convierte "/login.php" en "http://sitio.com/login.php".
            full_url: str = urljoin(url, href)

            # Limpio fragmentos (ej: #section1) porque apuntan a la misma página.
            full_url = full_url.split("#")[0]

            # Valido que la URL pertenezca al dominio objetivo.
            if self._is_in_scope(full_url):
                extracted_links.append(full_url)

        return extracted_links

    def _is_in_scope(self, url: str) -> bool:
        """
        Valida si una URL pertenece al dominio que estamos atacando.
        """
        parsed = urlparse(url)
        # Comparo el netloc (dominio) de la URL encontrada con el dominio base.
        # También me aseguro de que sea http o https.
        return parsed.netloc == self.base_domain and parsed.scheme in ["http", "https"]