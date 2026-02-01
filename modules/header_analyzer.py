#!/usr/bin/env python3.14
"""
HeaderAnalyzer - FASE 12: Auditoría de cabeceras de seguridad HTTP.
Detecta ausencia de headers críticos (X-Frame-Options, CSP, HSTS, etc).
"""

import requests
from typing import List
# --- CORRECCIÓN DE IMPORTS PARA COMPATIBILIDAD ---
from core.scanner_types import ScannerModule, Vulnerability, Target, Severity


class HeaderAnalyzer(ScannerModule):
    """Analizador de cabeceras de seguridad HTTP."""

    # Estas propiedades no son obligatorias en la nueva interfaz, pero está bien dejarlas
    @property
    def name(self) -> str:
        return "Header Security Audit"

    @property
    def description(self) -> str:
        return "Verifica ausencia de cabeceras de seguridad críticas (CSP, HSTS, etc)"

    def run(self, target: Target) -> List[Vulnerability]:
        """Ejecuta auditoría de headers con request HEAD ligero."""
        vulnerabilities: List[Vulnerability] = []

        try:
            # HEAD request ligero (no descarga contenido)
            # verify=False es necesario para entornos de prueba locales
            response = requests.head(
                target.url,
                timeout=10,
                allow_redirects=True,
                verify=False
            )

            headers = {k.lower(): v for k, v in response.headers.items()}

            # 1. X-Frame-Options (Clickjacking) → LOW
            if 'x-frame-options' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing X-Frame-Options",
                    description="Ausencia de X-Frame-Options expone a Clickjacking attacks",
                    severity=Severity.LOW,
                    target_url=target.url,
                    evidence="Header no encontrado en respuesta.",
                    payload="Recomendado: X-Frame-Options: DENY"
                ))

            # 2. Content-Security-Policy (XSS) → MEDIUM
            if 'content-security-policy' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing Content-Security-Policy",
                    description="Sin CSP permite ejecución de scripts maliciosos (XSS)",
                    severity=Severity.MEDIUM,
                    target_url=target.url,
                    evidence="Header no encontrado en respuesta.",
                    payload="Recomendado: Content-Security-Policy: default-src 'self'"
                ))

            # 3. Strict-Transport-Security (HSTS) → LOW
            if 'strict-transport-security' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing HSTS",
                    description="Sin HSTS permite downgrade attacks (HTTP)",
                    severity=Severity.LOW,
                    target_url=target.url,
                    evidence="Header no encontrado en respuesta.",
                    payload="Recomendado: Strict-Transport-Security: max-age=31536000"
                ))

            # 4. X-Content-Type-Options (MIME Sniffing) → LOW
            if 'x-content-type-options' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing X-Content-Type-Options",
                    description="Sin nosniff permite MIME type confusion attacks",
                    severity=Severity.LOW,
                    target_url=target.url,
                    evidence="Header no encontrado en respuesta.",
                    payload="Recomendado: X-Content-Type-Options: nosniff"
                ))

        except requests.RequestException as e:
            # Network error → no vuln, solo log
            pass

        return vulnerabilities