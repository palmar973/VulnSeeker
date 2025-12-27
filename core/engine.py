import logging
from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability, PageElement
from core.crawler import WebCrawler
from core.config import GlobalConfig

# Configuración de logging.
# NOTA DEL SENIOR: En el futuro, esto se conectará a la GUI para mostrar barras de progreso.
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class VulnSeekerEngine:
    """
    Orquestador central del sistema.
    Adaptado para manejar la nueva estructura 'PageElement' (Links y Formularios).
    """

    def __init__(self) -> None:
        self.modules: list[ScannerModule] = []
        self.results: list[Vulnerability] = []
        logger.info("VulnSeeker Engine: Sistema listo (Soporte Estructural Activado).")

    def register_module(self, module: ScannerModule) -> None:
        """Registra un módulo en el arsenal."""
        if not isinstance(module, ScannerModule):
            raise TypeError(f"Error de tipo: {type(module)} no es un ScannerModule válido.")

        self.modules.append(module)
        logger.debug(f"Módulo cargado: {module.name}")

    def scan(self, start_url: str, crawl: bool = True) -> list[Vulnerability]:
        """
        Método principal de orquestación.
        """
        logger.info(f"--- Iniciando operación sobre {start_url} ---")

        # Lista de elementos a atacar. Ahora no son solo strings, son objetos PageElement.
        target_elements: list[PageElement] = []

        if crawl:
            logger.info("Modo: BÚSQUEDA PROFUNDA (Crawling Links + Forms)")
            # Usamos la configuración global para el límite de páginas
            crawler = WebCrawler(start_url, max_pages=GlobalConfig.MAX_CRAWL_PAGES)
            target_elements = crawler.start()
        else:
            logger.info("Modo: OBJETIVO ÚNICO")
            # Si no hay crawling, creamos un elemento manual simple (GET por defecto)
            manual_element = PageElement(url=start_url, method="GET")
            target_elements = [manual_element]

        logger.info(f"Superficie de ataque identificada: {len(target_elements)} puntos de entrada.")

        # Fase de Ataque: Itero sobre cada elemento descubierto.
        for element in target_elements:
            self._analyze_single_element(element)

        logger.info("Operación finalizada.")
        return self.results

    def _analyze_single_element(self, element: PageElement) -> None:
        """
        Toma un elemento descubierto (Link o Formulario) y lo prepara para los módulos.
        """
        # Discriminación de Estrategia:
        # Por ahora, nuestros módulos (SQLi, XSS) funcionan sobre parámetros URL.
        # Si es un formulario POST, en el futuro necesitaremos lógica específica.

        logger.info(f"Analizando: [{element.method}] {element.url}")
        if element.is_form:
            logger.info(f"  -> Formulario detectado con campos: {list(element.params.keys())}")

        # Adaptador: Convertimos PageElement -> Target
        # Esto asegura que los módulos viejos sigan funcionando sin cambios.
        target = Target(
            url=element.url,
            method=element.method,
            # Pasamos los headers globales definidos en config
            headers={'User-Agent': GlobalConfig.USER_AGENT}
        )

        # Aquí podríamos inyectar los parámetros del formulario en el Target si fuera necesario.
        # Por ahora, dejamos que los módulos analicen la URL.

        for module in self.modules:
            try:
                # Lanzo el módulo.
                found_vulns: list[Vulnerability] = module.run(target)

                if found_vulns:
                    # Log visual para la terminal (luego será para la GUI)
                    logger.warning(f"  [!] {module.name} encontró {len(found_vulns)} fallos.")
                    self.results.extend(found_vulns)

            except Exception as e:
                logger.error(f"  [Error] Fallo en módulo {module.name}: {e}")