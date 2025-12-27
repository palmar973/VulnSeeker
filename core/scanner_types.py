from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass(frozen=True)
class PageElement:
    """
    Representa un elemento interactivo descubierto en una página.
    Esto permite al motor saber si debe enviar un GET simple o construir un POST.
    """
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    is_form: bool = False

@dataclass
class Target:
    """
    Representa el objetivo a escanear.
    Evolucionado para contener elementos descubiertos por el crawler.
    """
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    elements: List[PageElement] = field(default_factory=list)

@dataclass
class Vulnerability:
    """
    Estructura estándar para un hallazgo de seguridad.
    """
    name: str
    severity: Severity
    description: str
    target_url: str
    evidence: Optional[str] = None