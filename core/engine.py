import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability, PageElement
from core.crawler import WebCrawler
from core.config import GlobalConfig
from core.fingerprinter import TechFingerprinter  # 🆕 IMPORT

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class VulnSeekerEngine:
    """Orquestador de VulnSeeker."""

    def __init__(self) -> None:
        self.modules: list[ScannerModule] = []
        self.results: list[Vulnerability] = []
        self.fingerprint_data: str = "Unknown"  # 🆕 Atributo para guardar el resultado
        logger.info("VulnSeeker Engine: Sistema Multihilo Inicializado.")

    def register_module(self, module: ScannerModule) -> None:
        if not isinstance(module, ScannerModule):
            raise TypeError(f"El objeto {type(module)} no cumple con la interfaz ScannerModule.")
        self.modules.append(module)
        logger.debug(f"Módulo registrado: {module.name}")

    def scan(self, start_url: str, crawl: bool = True) -> list[Vulnerability]:
        """Punto de entrada principal."""
        logger.info(f"--- Iniciando Auditoría: {start_url} ---")

        # 🆕 FASE 19: Fingerprinting (El Detective)
        try:
            logger.info("🕵️‍♂️ Ejecutando análisis de tecnologías (Fingerprinting)...")
            fp = TechFingerprinter()
            analysis = fp.analyze(start_url)

            # Formatear bonito para la DB y la UI
            tech_parts = []
            if analysis['server']: tech_parts.append(f"Server: {', '.join(analysis['server'])}")
            if analysis['powered_by']: tech_parts.append(f"Backend: {', '.join(analysis['powered_by'])}")
            if analysis['cms_framework']: tech_parts.append(f"CMS: {', '.join(analysis['cms_framework'])}")

            self.fingerprint_data = " | ".join(tech_parts) if tech_parts else "Tecnología Genérica / Oculta"
            logger.info(f"✅ Tecnologías detectadas: {self.fingerprint_data}")

        except Exception as e:
            logger.error(f"⚠️ Error en fingerprinting: {e}")
            self.fingerprint_data = "Error en análisis"

        target_elements: list[PageElement] = []

        # FASE 1: Reconocimiento (Crawling)
        if crawl:
            logger.info("Ejecutando reconocimiento estructural...")
            crawler = WebCrawler(start_url, max_pages=GlobalConfig.MAX_CRAWL_PAGES)
            target_elements = crawler.start()
        else:
            target_elements = [PageElement(url=start_url, method="GET")]

        # FASE 2: Fase de Ataque (Concurrente)
        logger.info(f"Iniciando ataque sobre {len(target_elements)} elementos con {GlobalConfig.MAX_THREADS} hilos.")

        with ThreadPoolExecutor(max_workers=GlobalConfig.MAX_THREADS) as executor:
            future_to_element = {
                executor.submit(self._analyze_single_element, element): element
                for element in target_elements
            }

            for future in as_completed(future_to_element):
                try:
                    vulnerabilities_found = future.result()
                    if vulnerabilities_found:
                        self.results.extend(vulnerabilities_found)
                except Exception as e:
                    element = future_to_element[future]
                    logger.error(f"Excepción en hilo al analizar {element.url}: {e}")

        logger.info(f"Auditoría finalizada. {len(self.results)} vulnerabilidades.")
        return self.results

    def _analyze_single_element(self, element: PageElement) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        target = Target(
            url=element.url,
            method=element.method,
            headers={'User-Agent': GlobalConfig.USER_AGENT}
        )

        for module in self.modules:
            try:
                vulns = module.run(target)
                if vulns:
                    findings.extend(vulns)
            except Exception as e:
                logger.error(f"Módulo {module.name} falló en {element.url}: {e}")

        return findings