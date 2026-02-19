import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
# Necesario para extraer el dominio antes del recon de subdominios
from urllib.parse import urlparse
from core.scanner_types import Target, Vulnerability, PageElement, ScannerModule
from core.crawler import WebCrawler
from core.config import GlobalConfig
from core.fingerprinter import TechFingerprinter
from core.subdomain_scanner import SubdomainScanner

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class VulnSeekerEngine:
    """Orquestador Enterprise con Fingerprint + Subdomain Discovery."""

    def __init__(self, enable_subdomains: bool = True, config: dict | None = None) -> None:
        default_config = {
            "threads": 10,
            "user_agent": GlobalConfig.USER_AGENT,
            "enable_subdomains": True if config is None else True
        }
        if config is None:
            config = default_config
            config["enable_subdomains"] = enable_subdomains
        else:
            cfg = default_config.copy()
            cfg.update(config)
            config = cfg

        self.config = config
        self.modules: List[ScannerModule] = []
        self.results: List[Vulnerability] = []
        self.fingerprint_data: str = "Unknown"
        self.subdomain_data: List[str] = []
        self.tech_context: dict = {}
        self.enable_subdomains = self.config.get("enable_subdomains", True)
        logger.info("⚙️ VulnSeeker Engine inicializado (Subdomains: ON)" if self.enable_subdomains
                    else "⚙️ VulnSeeker Engine inicializado (Subdomains: OFF)")

    def register_module(self, module: ScannerModule) -> None:
        if not isinstance(module, ScannerModule):
            raise TypeError(f"El objeto {type(module)} no cumple con la interfaz ScannerModule.")
        self.modules.append(module)
        logger.debug(f"📦 Módulo registrado: {module.name}")

    def scan(self, start_url: str, crawl: bool = True) -> List[Vulnerability]:
        """Punto de entrada principal con recon OSINT expandido."""

        self.results = []  # Resetear resultados de escaneos anteriores
        if not start_url.startswith(('http://', 'https://')):
            start_url = 'http://' + start_url

        logger.info(f"🎯 --- AUDITORÍA ENTERPRISE: {start_url} ---")

        # FASE 0: SUBDOMAIN DISCOVERY (FASE 20)
        if self.config.get("enable_subdomains", True):
            self._run_subdomain_discovery(start_url)

        # FASE 1: FINGERPRINTING (Detective)
        try:
            logger.info("🕵️‍♂️ Análisis tecnológico activo...")
            fp = TechFingerprinter()
            tech_context = fp.analyze(start_url)

            tech_parts = []
            if tech_context['server']: tech_parts.append(f"Server: {', '.join(tech_context['server'])}")
            if tech_context['powered_by']: tech_parts.append(f"Backend: {', '.join(tech_context['powered_by'])}")
            if tech_context['cms_framework']: tech_parts.append(f"CMS: {', '.join(tech_context['cms_framework'])}")

            self.fingerprint_data = " | ".join(tech_parts) if tech_parts else "Tecnología Genérica"
            self.tech_context = tech_context or {}
            logger.info(f"🔬 Fingerprint: {self.fingerprint_data}")
        except Exception as e:
            logger.error(f"⚠️ Fingerprint falló: {e}")
            self.fingerprint_data = "Error en análisis"
            self.tech_context = {}

        # FASE 2: CRAWLING
        target_elements: List[PageElement] = []
        if crawl:
            logger.info("🕷️ Crawler estructural activo...")
            crawler = WebCrawler(start_url, max_pages=GlobalConfig.MAX_CRAWL_PAGES)
            target_elements = crawler.start()
        else:
            target_elements = [PageElement(url=start_url, method="GET")]

        logger.info(f"📍 {len(target_elements)} endpoints identificados.")

        # FASE 3: ATAQUE MULTIHILO
        if target_elements:
            logger.info(f"⚔️ Ataque coordinado: {len(self.modules)} módulos, {self.config.get('threads', 10)} hilos.")
            with ThreadPoolExecutor(max_workers=self.config.get("threads", 10)) as executor:
                future_to_element = {
                    executor.submit(self._analyze_single_element, element): element
                    for element in target_elements
                }

                for future in as_completed(future_to_element):
                    try:
                        vulns = future.result()
                        if vulns:
                            self.results.extend(vulns)
                    except Exception as e:
                        element = future_to_element[future]
                        logger.error(f"💥 Error hilo {element.url}: {e}")
        else:
            logger.warning("⚠️ No se encontraron endpoints para atacar. Verifica la URL.")

        logger.info(f"🏁 Auditoría completada: {len(self.results)} vulnerabilidades.")
        logger.info(f"🌐 Subdominios expandidos: {len(self.subdomain_data)}")
        return self.results

    def _run_subdomain_discovery(self, start_url: str) -> None:
        """Ejecuta el Conquistador OSINT."""
        try:
            parsed = urlparse(start_url)
            domain = parsed.netloc or parsed.path  # Maneja casos raros

            logger.info(f"🌐 Recon OSINT: {domain} (crt.sh Certificate Transparency)")

            scanner = SubdomainScanner()
            # Pasamos la URL completa; el scanner extrae el dominio base internamente
            self.subdomain_data = scanner.discover(start_url)

            if self.subdomain_data:
                logger.info(f"🎉 CONQUISTADOR: {len(self.subdomain_data)} subdominios LIVE:")
                for sub in self.subdomain_data[:5]:
                    logger.info(f"   👉 {sub}")
                if len(self.subdomain_data) > 5:
                    logger.info(f"   ...y {len(self.subdomain_data) - 5} más")
            else:
                logger.info("📭 No se encontraron subdominios adicionales.")

        except Exception as e:
            logger.error(f"⚠️ Error Subdomain Scanner: {e}")
            self.subdomain_data = []

    def _analyze_single_element(self, element: PageElement) -> List[Vulnerability]:
        """Análisis individual por hilo."""
        findings: List[Vulnerability] = []
        target = Target(
            url=element.url,
            method=element.method,
            headers={'User-Agent': self.config.get("user_agent", GlobalConfig.USER_AGENT)},
            elements=[element],
            context=self.tech_context
        )

        for module in self.modules:
            try:
                vulns = module.run(target)
                if vulns:
                    findings.extend(vulns)
            except Exception as e:
                logger.error(f"💥 Módulo {module.name} falló en {element.url}: {e}")

        return findings

    # GETTERS para UI/DB
    def get_subdomains(self) -> List[str]:
        return self.subdomain_data

    def get_fingerprint(self) -> str:
        return self.fingerprint_data

