from abc import ABC, abstractmethod
from typing import List
from core.models import Vulnerability, Severity

class ScannerModule(ABC):
    """Contrato base para que el motor mantenga polimorfismo estable."""

    @property
    @abstractmethod
    def name(self) -> str:
        # Nombre visible en logs
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    def run(self, target: Target) -> list[Vulnerability]:
        """
        Ejecuta la lógica de escaneo.
        Debe devolver una lista de vulnerabilidades, aunque esté vacía.
        """
        pass