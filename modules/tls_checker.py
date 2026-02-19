import ssl
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.TLS")

# Protocolos considerados inseguros
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TLSChecker(ScannerModule):
    """Verifica la configuración SSL/TLS del servidor para detectar
    problemas criptográficos: certificados vencidos, protocolos débiles,
    ausencia de HTTPS, etc."""

    @property
    def name(self) -> str:
        return "SSL/TLS Checker"

    @property
    def description(self) -> str:
        return "Verifica certificados SSL/TLS, protocolos débiles y configuración HTTPS."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        parsed = urlparse(target.url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not hostname:
            return vulns

        # 1. Verificar si el sitio usa HTTP en vez de HTTPS
        if parsed.scheme == "http":
            vulns.append(Vulnerability(
                name="No HTTPS",
                description=(
                    f"El sitio {hostname} usa HTTP sin cifrado. "
                    f"Toda la comunicación viaja en texto plano, incluyendo "
                    f"credenciales y datos sensibles."
                ),
                severity=Severity.HIGH,
                target_url=target.url,
                payload="http:// (sin TLS)"
            ))

        # 2. Intentar conectar vía TLS para analizar el certificado
        try:
            cert_info = self._get_certificate(hostname, port if parsed.scheme == "https" else 443)
            if cert_info:
                vulns.extend(self._check_certificate(cert_info, hostname, target.url))
        except Exception as e:
            logger.debug(f"No se pudo obtener certificado TLS de {hostname}: {e}")

        # 3. Verificar protocolos débiles
        try:
            weak = self._check_weak_protocols(hostname)
            vulns.extend(weak)
        except Exception as e:
            logger.debug(f"Error verificando protocolos TLS de {hostname}: {e}")

        return vulns

    def _get_certificate(self, hostname: str, port: int = 443) -> dict | None:
        """Obtiene el certificado X.509 del servidor."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert(binary_form=False)
                    if not cert:
                        # Reintentar con verificación para obtener info
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((hostname, port), timeout=5) as s2:
                            with ctx2.wrap_socket(s2, server_hostname=hostname) as t2:
                                return t2.getpeercert()
                    return cert
        except Exception:
            return None

    def _check_certificate(self, cert: dict, hostname: str, url: str) -> list[Vulnerability]:
        """Analiza el certificado en busca de problemas."""
        vulns = []

        # Verificar fecha de expiración
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                if expiry < now:
                    vulns.append(Vulnerability(
                        name="Expired SSL Certificate",
                        description=(
                            f"El certificado SSL de {hostname} expiró el {not_after}. "
                            f"Los navegadores mostrarán una advertencia de seguridad."
                        ),
                        severity=Severity.HIGH,
                        target_url=url,
                        payload=f"notAfter: {not_after}"
                    ))
                elif (expiry - now).days < 30:
                    vulns.append(Vulnerability(
                        name="SSL Certificate Expiring Soon",
                        description=(
                            f"El certificado SSL de {hostname} expira el {not_after} "
                            f"(en {(expiry - now).days} días)."
                        ),
                        severity=Severity.LOW,
                        target_url=url,
                        payload=f"notAfter: {not_after}"
                    ))
            except (ValueError, TypeError) as e:
                logger.debug(f"Error parseando fecha del certificado: {e}")

        return vulns

    def _check_weak_protocols(self, hostname: str) -> list[Vulnerability]:
        """Verifica si el servidor acepta protocolos TLS obsoletos."""
        vulns = []
        checks = [
            ("TLSv1", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]

        for proto_name, proto_version in checks:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = proto_version
                ctx.maximum_version = proto_version

                with socket.create_connection((hostname, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        vulns.append(Vulnerability(
                            name=f"Weak TLS Protocol ({proto_name})",
                            description=(
                                f"El servidor acepta {proto_name}, un protocolo "
                                f"obsoleto vulnerable a ataques como BEAST y POODLE."
                            ),
                            severity=Severity.MEDIUM,
                            target_url=f"https://{hostname}",
                            payload=f"Protocol: {proto_name}"
                        ))
            except (ssl.SSLError, OSError, ConnectionError):
                pass  # El servidor rechazó el protocolo — correcto
            except Exception as e:
                logger.debug(f"Error probando {proto_name}: {e}")

        return vulns
