import logging
import requests
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.BruteForce")

# Nombres comunes de campos de login
LOGIN_FIELD_NAMES = [
    "username", "user", "login", "email", "user_name",
    "uname", "usuario", "usr", "account", "nick",
]

PASSWORD_FIELD_NAMES = [
    "password", "pass", "passwd", "pwd", "clave",
    "contrasena", "secret", "user_pass", "login_password",
]

# Indicadores de CAPTCHA en formularios
CAPTCHA_INDICATORS = [
    "captcha", "recaptcha", "g-recaptcha", "h-captcha",
    "hcaptcha", "turnstile", "cf-turnstile", "securimage",
    "captcha_code", "verification_code",
]


class BruteForceDetector(ScannerModule):
    """Detecta formularios de login vulnerables a ataques de fuerza bruta (OWASP A07)."""

    @property
    def name(self) -> str:
        return "Brute Force Detector"

    @property
    def description(self) -> str:
        return "Identifica formularios de login sin protección contra ataques de fuerza bruta."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        for element in target.elements:
            try:
                # Solo formularios POST con campos de contraseña
                if not element.is_form or element.method.upper() != "POST":
                    continue

                param_names = [k.lower() for k in element.params.keys()]

                # Verificar si el form tiene campo de password
                has_password = any(
                    pwd_name in param
                    for param in param_names
                    for pwd_name in PASSWORD_FIELD_NAMES
                )

                if not has_password:
                    continue

                # Verificar si el form tiene campo de usuario
                has_login = any(
                    login_name in param
                    for param in param_names
                    for login_name in LOGIN_FIELD_NAMES
                )

                if not has_login:
                    continue

                # --- ES UN FORM DE LOGIN ---

                # Check 1: ¿Tiene CAPTCHA?
                has_captcha = any(
                    cap in param
                    for param in param_names
                    for cap in CAPTCHA_INDICATORS
                )

                if not has_captcha:
                    vulns.append(Vulnerability(
                        name="Login Without CAPTCHA",
                        description=(
                            f"El formulario de login no tiene protección CAPTCHA. "
                            f"Un atacante puede automatizar intentos de fuerza bruta "
                            f"sin restricción humana. Campos: {', '.join(element.params.keys())}."
                        ),
                        severity=Severity.HIGH,
                        target_url=element.url,
                        payload=f"POST {element.url} (sin CAPTCHA)"
                    ))

                # Check 2: ¿Tiene protección de rate limiting?
                self._check_rate_limiting(element, target.headers, vulns)

                # Check 3: ¿Tiene account lockout?
                has_lockout_field = any(
                    hint in param
                    for param in param_names
                    for hint in ["attempts", "lockout", "tries", "remaining"]
                )

                if not has_lockout_field and not has_captcha:
                    vulns.append(Vulnerability(
                        name="No Account Lockout Detected",
                        description=(
                            f"El formulario de login no muestra indicadores de bloqueo por "
                            f"intentos fallidos. Sin lockout + sin CAPTCHA = brute force viable."
                        ),
                        severity=Severity.MEDIUM,
                        target_url=element.url,
                        payload=f"POST {element.url} (sin lockout policy)"
                    ))

            except Exception as e:
                logger.error(f"Error analizando formulario brute force: {e}")

        return vulns

    def _check_rate_limiting(self, element, headers: dict, vulns: list) -> None:
        """Envía 3 requests rápidos para detectar si hay rate limiting."""
        try:
            test_data = {}
            for k in element.params:
                test_data[k] = "test_bf_check"

            responses = []
            for _ in range(3):
                resp = requests.post(
                    element.url,
                    data=test_data,
                    headers=headers,
                    timeout=5,
                    allow_redirects=True
                )
                responses.append(resp)

            # Si los 3 requests devuelven 200 (no 429 Too Many Requests)
            # no hay rate limiting detectable
            all_ok = all(r.status_code != 429 for r in responses)
            has_retry = any("retry-after" in r.headers for r in responses)

            if all_ok and not has_retry:
                vulns.append(Vulnerability(
                    name="No Rate Limiting",
                    description=(
                        f"El endpoint de login no implementa rate limiting. "
                        f"3 requests consecutivos recibieron respuesta sin bloqueo (HTTP 429). "
                        f"Esto permite ataques de fuerza bruta automatizados a alta velocidad."
                    ),
                    severity=Severity.HIGH,
                    target_url=element.url,
                    payload=f"3x POST {element.url} → sin HTTP 429"
                ))

        except requests.RequestException as e:
            logger.debug(f"Rate limit check falló (red): {e}")
        except Exception as e:
            logger.error(f"Error en rate limiting check: {e}")
