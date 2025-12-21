from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Target:
    """
    Representa el objetivo a escanear.
    """
    url: str
    method: str = "GET"
    # Decido usar un diccionario vacío por defecto para headers para no tener problemas de mutabilidad compartida.
    headers: dict[str, str] = field(default_factory=dict)

@dataclass
class Vulnerability:
    """
    Estructura estándar para un hallazgo de seguridad.
    """
    name: str
    severity: Severity
    description: str
    target_url: str
    # A veces no tendré evidencia clara (como en una inyección a ciegas), así que lo dejo opcional.
    evidence: str | None = None