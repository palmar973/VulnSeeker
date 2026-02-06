"""Estructuras base; separa tipos comunes para evitar dependencias circulares."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self):
        return self.value

@dataclass
class Vulnerability:
    name: str
    description: str
    severity: Severity | str  # Admite Enum o String para compatibilidad
    target_url: str
    payload: Optional[str] = None
    evidence: Optional[str] = None