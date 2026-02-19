import logging
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.CSRF")

# Nombres comunes de tokens anti-CSRF en formularios
CSRF_TOKEN_NAMES = [
    "csrf", "xsrf", "_token", "csrf_token", "_csrf_token",
    "csrfmiddlewaretoken", "authenticity_token", "anti_forgery",
    "__requestverificationtoken", "xsrf_token", "nonce",
]


class CSRFAuditor(ScannerModule):
    """Analiza formularios POST para detectar la ausencia de tokens anti-CSRF."""

    @property
    def name(self) -> str:
        return "CSRF Auditor"

    @property
    def description(self) -> str:
        return "Analiza formularios POST en busca de tokens anti-CSRF faltantes."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        for element in target.elements:
            try:
                # Solo evaluar formularios POST (los GET no cambian estado)
                if not element.is_form or element.method.upper() != "POST":
                    continue

                param_names = [k.lower() for k in element.params.keys()]

                # Verificar si algún campo parece un token anti-CSRF
                has_csrf_token = any(
                    token_name in param
                    for param in param_names
                    for token_name in CSRF_TOKEN_NAMES
                )

                if not has_csrf_token:
                    field_names = ", ".join(element.params.keys()) or "(sin campos)"
                    vulns.append(Vulnerability(
                        name="Missing CSRF Token",
                        description=(
                            f"El formulario POST no contiene ningún token anti-CSRF. "
                            f"Campos encontrados: {field_names}. "
                            f"Un atacante podría forzar acciones en nombre del usuario."
                        ),
                        severity=Severity.MEDIUM,
                        target_url=element.url,
                        payload=f"POST {element.url} (campos: {field_names})"
                    ))

            except Exception as e:
                logger.error(f"Error analizando formulario CSRF: {e}")

        return vulns
