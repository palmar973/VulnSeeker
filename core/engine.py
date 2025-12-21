import logging
from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability
from core.crawler import WebCrawler

# Configuro el logging básico.
# En el futuro moveré esto a una clase de configuración, pero por ahora me sirve aquí.
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class VulnSeekerEngine:
    """
    Orquestador central.
    Responsable de coordinar el descubrimiento (Crawler) y el ataque (Modules).
    """

    def __init__(self) -> None:
        self.modules: list[ScannerModule] = []
        self.results: list[Vulnerability] = []
        logging.info("VulnSeeker Engine: Cerebro inicializado y listo.")

    def register_module(self, module: ScannerModule) -> None:
        """Registra un módulo en el arsenal de ataque."""
        if not isinstance(module, ScannerModule):
            # Soy estricto con los tipos. Si no es un módulo válido, no entra.
            raise TypeError(f"Error de tipo: {type(module)} no es un ScannerModule válido.")

        self.modules.append(module)
        logging.debug(f"Módulo cargado exitosamente: {module.name}")

    def scan(self, start_url: str, crawl: bool = True) -> list[Vulnerability]:
        """
        Método principal de orquestación.

        Args:
            start_url: La URL semilla donde comienza la operación.
            crawl: Define si activo el Crawler (True) o ataco directo (False).
        """
        logging.info(f"--- Iniciando operación sobre {start_url} ---")

        target_urls: list[str] = []

        if crawl:
            logging.info("Modo activado: BÚSQUEDA Y DESTRUCCIÓN (Crawling)")
            # Instancio el Crawler.
            # Le pongo un límite de 10 páginas para mantener las pruebas ágiles.
            crawler = WebCrawler(start_url, max_pages=10)
            target_urls = crawler.start()
        else:
            logging.info("Modo activado: FRANCOTIRADOR (Ataque puntual)")
            target_urls = [start_url]

        logging.info(f"Objetivos identificados para análisis: {len(target_urls)}")

        # Fase de Ataque: Itero sobre cada URL descubierta.
        for url in target_urls:
            self._analyze_single_target(url)

        logging.info("Operación finalizada. Generando reporte de resultados...")
        return self.results

    def _analyze_single_target(self, url: str) -> None:
        """
        Método interno helper.
        Toma una URL y le lanza TODO el arsenal de módulos disponibles.
        """
        logging.info(f"Analizando objetivo específico: {url}")

        # Creo el objeto Target. Asumo method="GET" por defecto.
        target = Target(url=url)

        for module in self.modules:
            try:
                # Lanzo el módulo actual contra el objetivo.
                found_vulns: list[Vulnerability] = module.run(target)

                if found_vulns:
                    logging.warning(f"  [!] {module.name} detectó {len(found_vulns)} incidencias en {url}")
                    self.results.extend(found_vulns)

            except Exception as e:
                # Si un módulo falla, lo registro y sigo con el siguiente.
                # No puedo permitir que un error de plugin detenga el motor.
                logging.error(f"  [Error] Fallo crítico en módulo {module.name} procesando {url}: {e}")