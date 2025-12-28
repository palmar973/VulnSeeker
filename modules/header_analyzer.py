#!/usr/bin/env python3.14
"""
HeaderAnalyzer - FASE 12: Auditoría de cabeceras de seguridad HTTP.
Detecta ausencia de headers críticos (X-Frame-Options, CSP, HSTS, etc).
"""

import requests
from typing import List
from core.models import Vulnerability, Severity
from core.interfaces import ScannerModule


class HeaderAnalyzer(ScannerModule):
    """Analizador de cabeceras de seguridad HTTP."""

    @property
    def name(self) -> str:
        return "Header Security Audit"

    @property
    def description(self) -> str:
        return "Verifica ausencia de cabeceras de seguridad críticas (CSP, HSTS, etc)"

    def run(self, target: 'Target') -> List[Vulnerability]:
        """Ejecuta auditoría de headers con request HEAD ligero."""
        vulnerabilities: List[Vulnerability] = []

        try:
            # HEAD request ligero (no descarga contenido)
            response = requests.head(
                target.url,
                timeout=10,
                allow_redirects=True,
                verify=False  # Para targets HTTPS self-signed
            )

            headers = response.headers
            checked_headers = []

            # 1. X-Frame-Options (Clickjacking) → LOW
            if 'x-frame-options' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing X-Frame-Options",
                    description="Ausencia de X-Frame-Options expone a Clickjacking attacks",
                    severity=Severity.LOW,
                    target_url=target.url,
                    payload="Recomendado: X-Frame-Options: DENY"
                ))
                checked_headers.append("X-Frame-Options")

            # 2. Content-Security-Policy (XSS) → MEDIUM
            if 'content-security-policy' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing Content-Security-Policy",
                    description="Sin CSP permite ejecución de scripts maliciosos (XSS)",
                    severity=Severity.MEDIUM,
                    target_url=target.url,
                    payload="Recomendado: Content-Security-Policy: default-src 'self'"
                ))
                checked_headers.append("CSP")

            # 3. Strict-Transport-Security (HSTS) → LOW
            if 'strict-transport-security' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing HSTS",
                    description="Sin HSTS permite downgrade attacks (HTTP)",
                    severity=Severity.LOW,
                    target_url=target.url,
                    payload="Recomendado: Strict-Transport-Security: max-age=31536000"
                ))
                checked_headers.append("HSTS")

            # 4. X-Content-Type-Options (MIME Sniffing) → LOW
            if 'x-content-type-options' not in headers:
                vulnerabilities.append(Vulnerability(
                    name="Missing X-Content-Type-Options",
                    description="Sin nosniff permite MIME type confusion attacks",
                    severity=Severity.LOW,
                    target_url=target.url,
                    payload="Recomendado: X-Content-Type-Options: nosniff"
                ))
                checked_headers.append("X-Content-Type-Options")

        except requests.RequestException as e:
            # Network error → no vuln, solo log
            pass

        return vulnerabilities