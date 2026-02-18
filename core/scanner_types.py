"""
Re-exportador de compatibilidad.
Todos los tipos canónicos se definen en core.models.
Este archivo existe para no romper imports existentes.
"""

from core.models import (
    Severity,
    PageElement,
    Target,
    Vulnerability,
    ScannerModule,
)

__all__ = [
    "Severity",
    "PageElement",
    "Target",
    "Vulnerability",
    "ScannerModule",
]