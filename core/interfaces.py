from abc import ABC, abstractmethod
from core.scanner_types import Target, Vulnerability

class ScannerModule(ABC):
    """
    Clase base abstracta. Obligo a cualquier módulo futuro a seguir esta estructura
    para no romper el polimorfismo del motor.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        # Necesito un nombre para los logs, si no, no sabré quién está escaneando.
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        # Una breve descripción para el reporte final.
        pass

    @abstractmethod
    def run(self, target: Target) -> list[Vulnerability]:
        """
        Ejecuta la lógica de escaneo.
        Debe devolver una lista de vulnerabilidades, aunque esté vacía.
        """
        pass