"""
Archivo canónico de tipos de VulnSeeker.
Todas las estructuras de datos y la interfaz base del sistema se definen aquí.
"""

from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Niveles de criticidad siguiendo estándares de industria."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self):
        return self.value


@dataclass(frozen=True)
class PageElement:
    """Punto de ataque descubierto (URL o form); frozen para seguridad entre hilos."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    is_form: bool = False


@dataclass
class Target:
    """Entrada estándar para los módulos de escaneo."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    elements: List[PageElement] = field(default_factory=list)
    context: Dict[str, object] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Hallazgo de seguridad detectado por un módulo."""
    name: str
    severity: Severity
    description: str
    target_url: str
    evidence: Optional[str] = None
    payload: Optional[str] = None


class ScannerModule:
    """Interfaz base que todo módulo de escaneo debe implementar."""

    @property
    def name(self) -> str:
        raise NotImplementedError("Cada módulo debe definir su nombre.")

    @property
    def description(self) -> str:
        raise NotImplementedError("Cada módulo debe definir su descripción.")

    @abstractmethod
    def run(self, target: Target) -> List[Vulnerability]:
        raise NotImplementedError("Cada módulo debe implementar el método run().")