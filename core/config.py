from dataclasses import dataclass


@dataclass(frozen=True)
class GlobalConfig:
    """
    Configuración global del sistema VulnSeeker.
    Centralizamos parámetros para facilitar la defensa académica de la tesis.
    """
    # Identidad del escáner
    USER_AGENT: str = "VulnSeeker/1.0 (Academic Security Scanner)"

    # Límites del Crawler
    MAX_CRAWL_PAGES: int = 50

    # Límites del Motor (Performance)
    # 10 hilos es el punto dulce entre velocidad y estabilidad.
    MAX_THREADS: int = 10

    # Timeouts de red (en segundos)
    REQUEST_TIMEOUT: int = 5

    # Directorio de salida para reportes (¡Recuperado!)
    REPORTS_DIR: str = "results"