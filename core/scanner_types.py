from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from core.models import Vulnerability, Severity

class Severity(Enum):
    """Niveles de criticidad siguiendo estándares de industria."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass(frozen=True)
class PageElement:
    """
    Punto de ataque descubierto (URL o form); frozen para evitar líos de mutabilidad entre hilos.
    """
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    is_form: bool = False

@dataclass
class Target:
    """Entrada estándar para los módulos (mantiene compat con SQLi/XSS iniciales)."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    elements: List[PageElement] = field(default_factory=list)
    context: Dict[str, object] = field(default_factory=dict)

@dataclass
class Vulnerability:
    """Define un hallazgo de seguridad."""
    name: str
    severity: Severity
    description: str
    target_url: str
    evidence: Optional[str] = None
    payload: Optional[str] = None  # Compatibilidad con reportes que esperan 'payload'

# --- AGREGADO PARA SOPORTE DE NUEVOS MÓDULOS ---
class ScannerModule:
    """Interfaz mínima que el motor valida en cada módulo."""
    def run(self, target: Target) -> List[Vulnerability]:
        raise NotImplementedError("Cada módulo debe implementar el método run()")