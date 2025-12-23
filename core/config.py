from dataclasses import dataclass


@dataclass(frozen=True)
class GlobalConfig:
    """
    Configuración global inmutable del sistema.
    Centraliza parámetros como timeouts, headers y concurrencia.
    """
    # Identidad del escáner (User-Agent)
    USER_AGENT: str = "VulnSeeker-Academic/1.0 (Educational Purpose)"

    # Tiempo máximo de espera por petición (segundos)
    REQUEST_TIMEOUT: int = 5

    # Límite de profundidad o páginas para el crawler
    MAX_CRAWL_PAGES: int = 20

    # Carpeta donde se guardarán los reportes
    REPORTS_DIR: str = "results"