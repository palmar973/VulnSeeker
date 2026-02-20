import logging
import requests
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.CORS")

# Origin malicioso para probar si el servidor lo refleja
EVIL_ORIGIN = "https://evil-attacker.com"


class CORSMisconfigScanner(ScannerModule):
    """Detecta configuraciones inseguras de CORS (OWASP A05)."""

    @property
    def name(self) -> str:
        return "CORS Misconfiguration Scanner"

    @property
    def description(self) -> str:
        return "Detecta políticas CORS permisivas que permiten acceso cross-origin no autorizado."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}

            # Enviar request con Origin malicioso para ver si lo refleja
            headers["Origin"] = EVIL_ORIGIN
            response = requests.get(
                target.url, headers=headers, timeout=5, verify=False
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                return vulns  # No hay CORS headers → no aplica

            logger.info(f"🌐 CORS: {target.url} → ACAO={acao}")

            # Check 1: Wildcard (*) permite acceso desde cualquier origen
            if acao == "*":
                vulns.append(Vulnerability(
                    name="CORS Wildcard Origin",
                    description=(
                        "El servidor responde con Access-Control-Allow-Origin: *. "
                        "Cualquier sitio web puede hacer requests cross-origin a este recurso, "
                        "exponiendo datos sensibles a atacantes."
                    ),
                    severity=Severity.MEDIUM,
                    target_url=target.url,
                    payload="Access-Control-Allow-Origin: *"
                ))

                # Wildcard + Credentials = crítico
                if acac.lower() == "true":
                    vulns.append(Vulnerability(
                        name="CORS Wildcard With Credentials",
                        description=(
                            "El servidor permite CORS wildcard Y cookies/credenciales. "
                            "Esto permite a cualquier sitio hacer requests autenticados "
                            "y leer las respuestas, comprometiendo la sesión del usuario."
                        ),
                        severity=Severity.CRITICAL,
                        target_url=target.url,
                        payload="ACAO: * + ACAC: true"
                    ))

            # Check 2: El servidor refleja nuestro origin malicioso
            elif acao == EVIL_ORIGIN:
                sev = Severity.HIGH
                desc = (
                    f"El servidor refleja el Origin del atacante ({EVIL_ORIGIN}) en "
                    f"Access-Control-Allow-Origin. Un atacante puede robar datos "
                    f"cross-origin desde su dominio malicioso."
                )

                if acac.lower() == "true":
                    sev = Severity.CRITICAL
                    desc += (
                        " AGRAVANTE: Allow-Credentials está habilitado, "
                        "permitiendo robo de sesión completo."
                    )

                vulns.append(Vulnerability(
                    name="CORS Origin Reflection",
                    description=desc,
                    severity=sev,
                    target_url=target.url,
                    payload=f"Origin: {EVIL_ORIGIN} → ACAO: {acao}, ACAC: {acac}"
                ))

            # Check 3: Origin null aceptado (bypass común)
            self._check_null_origin(target, vulns)

        except requests.RequestException as e:
            logger.debug(f"Error de conexión CORS: {e}")
        except Exception as e:
            logger.error(f"Error en CORSMisconfigScanner: {e}")

        return vulns

    def _check_null_origin(self, target, vulns):
        """Verifica si el servidor acepta Origin: null (bypass de sandboxes)."""
        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            headers["Origin"] = "null"
            response = requests.get(
                target.url, headers=headers, timeout=5, verify=False
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            if acao == "null":
                vulns.append(Vulnerability(
                    name="CORS Null Origin Accepted",
                    description=(
                        "El servidor acepta Origin: null en CORS. "
                        "Iframes sandboxed y data URIs envían Origin: null, "
                        "permitiendo bypass de restricciones CORS."
                    ),
                    severity=Severity.HIGH,
                    target_url=target.url,
                    payload="Origin: null → ACAO: null"
                ))

        except requests.RequestException:
            pass
