import logging
import math
import requests
from collections import Counter
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.WeakSession")

# Nombres comunes de cookies de sesión
SESSION_COOKIE_NAMES = [
    "phpsessid", "jsessionid", "asp.net_sessionid", "sessionid",
    "session_id", "sid", "sess", "token", "session", "connect.sid",
]


class WeakSessionAuditor(ScannerModule):
    """Audita la fortaleza de tokens de sesión (OWASP A07)."""

    @property
    def name(self) -> str:
        return "Weak Session Auditor"

    @property
    def description(self) -> str:
        return "Evalúa entropía, predictibilidad y flags de cookies de sesión."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            session = requests.Session()
            response = session.get(
                target.url, headers=headers, timeout=10,
                verify=False, allow_redirects=True
            )

            if not session.cookies:
                return vulns

            for cookie in session.cookies:
                cookie_name_lower = cookie.name.lower()

                # Solo auditar cookies que parezcan de sesión
                is_session = any(
                    s in cookie_name_lower for s in SESSION_COOKIE_NAMES
                )
                if not is_session:
                    continue

                logger.info(f"🔑 Auditando sesión: {cookie.name}")

                # Check 1: Entropía del valor (predictibilidad)
                self._check_entropy(cookie, vulns, target.url)

                # Check 2: Longitud mínima del token
                self._check_length(cookie, vulns, target.url)

                # Check 3: SameSite attribute
                self._check_samesite(cookie, vulns, target.url)

                # Check 4: Session fixation (¿cambia el ID tras re-request?)
                self._check_fixation(cookie, target, session, vulns)

        except requests.RequestException as e:
            logger.debug(f"Error de conexión: {e}")
        except Exception as e:
            logger.error(f"Error en WeakSessionAuditor: {e}")

        return vulns

    def _check_entropy(self, cookie, vulns, url):
        """Verifica que el token tenga suficiente entropía (aleatoriedad)."""
        value = cookie.value
        if not value:
            return

        entropy = self._calculate_entropy(value)

        # Un buen token de sesión debe tener >3.5 bits de entropía por carácter
        if entropy < 3.0:
            vulns.append(Vulnerability(
                name="Low Session Token Entropy",
                description=(
                    f"La cookie de sesión '{cookie.name}' tiene baja entropía "
                    f"({entropy:.2f} bits/char). Tokens predecibles permiten "
                    f"a un atacante adivinar sesiones válidas."
                ),
                severity=Severity.HIGH,
                target_url=url,
                payload=f"{cookie.name}={value[:8]}... (entropía: {entropy:.2f})"
            ))

    def _check_length(self, cookie, vulns, url):
        """Tokens de sesión demasiado cortos son inseguros."""
        value = cookie.value
        if len(value) < 16:
            vulns.append(Vulnerability(
                name="Short Session Token",
                description=(
                    f"La cookie '{cookie.name}' tiene un token de solo "
                    f"{len(value)} caracteres. OWASP recomienda mínimo 16 "
                    f"caracteres para prevenir ataques de fuerza bruta."
                ),
                severity=Severity.MEDIUM,
                target_url=url,
                payload=f"{cookie.name}={value} (len={len(value)})"
            ))

    def _check_samesite(self, cookie, vulns, url):
        """Verifica que SameSite esté establecido."""
        rest = getattr(cookie, "_rest", {})
        has_samesite = any("samesite" in k.lower() for k in rest.keys())

        if not has_samesite:
            vulns.append(Vulnerability(
                name="Missing SameSite Attribute",
                description=(
                    f"La cookie de sesión '{cookie.name}' no tiene el atributo "
                    f"SameSite. Sin esta protección, la cookie se envía en "
                    f"requests cross-origin, facilitando ataques CSRF."
                ),
                severity=Severity.MEDIUM,
                target_url=url,
                payload=f"Set-Cookie: {cookie.name}=...; (sin SameSite)"
            ))

    def _check_fixation(self, cookie, target, session, vulns):
        """Detecta session fixation: si el ID no cambia al re-solicitar."""
        try:
            original_id = cookie.value
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}

            # Hacer un nuevo request SIN la session cookie anterior
            new_session = requests.Session()
            new_session.get(
                target.url, headers=headers, timeout=10,
                verify=False, allow_redirects=True
            )

            for new_cookie in new_session.cookies:
                if new_cookie.name == cookie.name:
                    if new_cookie.value == original_id:
                        vulns.append(Vulnerability(
                            name="Possible Session Fixation",
                            description=(
                                f"La cookie '{cookie.name}' devuelve el mismo valor "
                                f"en requests sin sesión. El servidor podría no estar "
                                f"regenerando el ID de sesión, permitiendo fixation."
                            ),
                            severity=Severity.HIGH,
                            target_url=target.url,
                            payload=f"ID fijo: {original_id[:12]}..."
                        ))
                    break

        except requests.RequestException:
            pass

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calcula la entropía de Shannon de un string (bits por carácter)."""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
