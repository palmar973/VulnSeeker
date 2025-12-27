import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability, PageElement
from core.crawler import WebCrawler
from core.config import GlobalConfig

# Configuración básica de logeo.
# Aquí decidí no usar f-strings en el logger por convención de performance.
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class VulnSeekerEngine:
    """
    Orquestador de VulnSeeker.
    Se encarga de coordinar el Crawling y la fase de ataque concurrente.
    """

    def __init__(self) -> None:
        self.modules: list[ScannerModule] = []
        self.results: list[Vulnerability] = []
        logger.info("VulnSeeker Engine: Sistema Multihilo Inicializado correctamente.")

    def register_module(self, module: ScannerModule) -> None:
        """Añade un módulo de seguridad al motor de escaneo."""
        if not isinstance(module, ScannerModule):
            raise TypeError(f"El objeto {type(module)} no cumple con la interfaz ScannerModule.")
        self.modules.append(module)
        logger.debug(f"Módulo registrado: {module.name}")

    def scan(self, start_url: str, crawl: bool = True) -> list[Vulnerability]:
        """
        Punto de entrada principal para el proceso de auditoría.
        """
        logger.info(f"--- Iniciando Auditoría: {start_url} ---")

        target_elements: list[PageElement] = []

        # FASE 1: Reconocimiento (Crawling)
        if crawl:
            logger.info("Ejecutando reconocimiento estructural...")
            crawler = WebCrawler(start_url, max_pages=GlobalConfig.MAX_CRAWL_PAGES)
            target_elements = crawler.start()
        else:
            # Modo objetivo único: creamos un elemento manual para no romper el bucle.
            target_elements = [PageElement(url=start_url, method="GET")]

        # FASE 2: Fase de Ataque (Concurrente)
        logger.info(
            f"Iniciando fase de ataque sobre {len(target_elements)} elementos con {GlobalConfig.MAX_THREADS} hilos.")

        # Uso el context manager para asegurar que los hilos se limpien al terminar.
        with ThreadPoolExecutor(max_workers=GlobalConfig.MAX_THREADS) as executor:
            # Lanzo las tareas de análisis.
            future_to_element = {
                executor.submit(self._analyze_single_element, element): element
                for element in target_elements
            }

            # Recolecto los resultados a medida que cada hilo termina su trabajo.
            for future in as_completed(future_to_element):
                try:
                    vulnerabilities_found = future.result()
                    if vulnerabilities_found:
                        # Extend es una operación segura en este contexto de CPython.
                        self.results.extend(vulnerabilities_found)
                except Exception as e:
                    element = future_to_element[future]
                    logger.error(f"Excepción en hilo al analizar {element.url}: {e}")

        logger.info(f"Auditoría finalizada. Se detectaron {len(self.results)} vulnerabilidades.")
        return self.results

    def _analyze_single_element(self, element: PageElement) -> list[Vulnerability]:
        """
        Lógica interna para correr todos los módulos sobre un elemento específico.
        Este método corre dentro de un hilo individual.
        """
        findings: list[Vulnerability] = []

        # Mapeo de PageElement a Target para compatibilidad con el ecosistema de módulos.
        target = Target(
            url=element.url,
            method=element.method,
            headers={'User-Agent': GlobalConfig.USER_AGENT}
        )

        for module in self.modules:
            try:
                # Ejecución del módulo (aquí ocurre el I/O intenso).
                vulns = module.run(target)
                if vulns:
                    findings.extend(vulns)
            except Exception as e:
                # Espero que un error en XSS no detenga el análisis de SQLi.
                logger.error(f"Módulo {module.name} falló en {element.url}: {e}")

        return findings