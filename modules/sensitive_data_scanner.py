import logging
import re
import requests
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.SensitiveData")

# Patrones de datos sensibles con sus nombres y severidades
SENSITIVE_PATTERNS = [
    # API Keys y Tokens
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', "API Key Exposed", Severity.CRITICAL),
    (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', "Secret Key Exposed", Severity.CRITICAL),
    (r'(?:access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', "Access Token Exposed", Severity.CRITICAL),

    # AWS Keys
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", Severity.CRITICAL),

    # Contraseñas hardcoded
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Hardcoded Password", Severity.HIGH),

    # Emails internos
    (r'[a-zA-Z0-9._%+-]+@(?:internal|corp|admin|dev)\.[a-zA-Z]{2,}', "Internal Email Exposed", Severity.LOW),

    # Tarjetas de crédito (Visa, Mastercard, Amex)
    (r'\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b', "Credit Card Number (Visa)", Severity.CRITICAL),
    (r'\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b', "Credit Card Number (Mastercard)", Severity.CRITICAL),

    # Rutas internas del servidor
    (r'(?:C:\\\\[Uu]sers\\\\|/home/\w+/|/var/www/|/etc/passwd)', "Internal Server Path Exposed", Severity.MEDIUM),

    # Comentarios HTML con información sensible
    (r'<!--\s*(?:TODO|FIXME|HACK|BUG|password|secret|admin|root).*?-->', "Sensitive HTML Comment", Severity.LOW),

    # Conexiones de base de datos
    (r'(?:jdbc:|mysql://|postgres://|mongodb://)\S+', "Database Connection String", Severity.HIGH),

    # Private Keys
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key Exposed", Severity.CRITICAL),
]


class SensitiveDataExposure(ScannerModule):
    """Detecta datos sensibles expuestos en código fuente HTML (OWASP A02)."""

    @property
    def name(self) -> str:
        return "Sensitive Data Exposure"

    @property
    def description(self) -> str:
        return "Busca API keys, contraseñas, tarjetas y datos sensibles en el HTML."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            response = requests.get(
                target.url, headers=headers, timeout=5, verify=False
            )

            if "text/html" not in response.headers.get("Content-Type", ""):
                return vulns

            html = response.text

            for pattern, vuln_name, severity in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, html, re.IGNORECASE)

                if matches:
                    # Limitar a 3 evidencias por tipo para evitar spam
                    evidence = matches[:3]
                    evidence_str = ", ".join(
                        str(m)[:30] + "..." if len(str(m)) > 30 else str(m)
                        for m in evidence
                    )

                    vulns.append(Vulnerability(
                        name=vuln_name,
                        description=(
                            f"Se detectaron {len(matches)} instancia(s) de "
                            f"'{vuln_name}' en el código fuente de la página. "
                            f"Datos sensibles expuestos públicamente pueden ser "
                            f"explotados por atacantes."
                        ),
                        severity=severity,
                        target_url=target.url,
                        payload=f"Muestras: {evidence_str}"
                    ))

                    logger.warning(
                        f"  [!] {vuln_name}: {len(matches)} coincidencia(s) en {target.url}"
                    )

        except requests.RequestException as e:
            logger.debug(f"Error de conexión: {e}")
        except Exception as e:
            logger.error(f"Error en SensitiveDataExposure: {e}")

        return vulns
