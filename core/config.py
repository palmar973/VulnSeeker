from dataclasses import dataclass


@dataclass(frozen=True)
class GlobalConfig:
    """
    Configuración global del sistema VulnSeeker.
    Centralizamos parámetros para facilitar la defensa académica de la tesis.
    """
    USER_AGENT: str = "VulnSeeker/1.0 (Academic Security Scanner)"

    MAX_CRAWL_PAGES: int = 50

    # Profundidad máxima de crawling (previene spider traps)
    MAX_CRAWL_DEPTH: int = 4

    # 10 hilos es el punto dulce entre velocidad y estabilidad.
    MAX_THREADS: int = 10

    REQUEST_TIMEOUT: int = 5

    REPORTS_DIR: str = "results"