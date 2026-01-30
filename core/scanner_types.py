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

@dataclass(frozen=True)
class PageElement:
    """
    Representa un punto de ataque descubierto (URL o Formulario).
    Lo marqué como frozen=True para evitar errores de mutabilidad entre hilos.
    """
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    is_form: bool = False

@dataclass
class Target:
    """
    Estructura que reciben los módulos de ataque.
    Mantenemos compatibilidad con los módulos SQLi y XSS iniciales.
    """
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    # Lista de elementos internos descubiertos si se requiere un análisis profundo.
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