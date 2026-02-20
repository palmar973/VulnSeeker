import logging
import requests
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.HTTPMethods")

# Métodos peligrosos que no deberían estar habilitados en producción
DANGEROUS_METHODS = {
    "PUT": ("Permite subir archivos al servidor remotamente.", Severity.HIGH),
    "DELETE": ("Permite eliminar recursos del servidor remotamente.", Severity.HIGH),
    "TRACE": ("Habilita ataques Cross-Site Tracing (XST) para robar cookies.", Severity.MEDIUM),
    "CONNECT": ("Puede ser abusado como proxy abierto.", Severity.MEDIUM),
    "PATCH": ("Permite modificar recursos parcialmente sin autorización.", Severity.MEDIUM),
}


class HTTPMethodTamperingScanner(ScannerModule):
    """Detecta métodos HTTP peligrosos habilitados en el servidor (OWASP A05)."""

    @property
    def name(self) -> str:
        return "HTTP Method Tampering Scanner"

    @property
    def description(self) -> str:
        return "Identifica métodos HTTP peligrosos habilitados (PUT, DELETE, TRACE, etc.)."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        # Check 1: OPTIONS para descubrir métodos permitidos
        self._check_options(target, vulns)

        # Check 2: Probar cada método peligroso directamente
        self._probe_methods(target, vulns)

        return vulns

    def _check_options(self, target, vulns):
        """Envía OPTIONS para ver qué métodos anuncia el servidor."""
        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            response = requests.options(
                target.url, headers=headers, timeout=5, verify=False
            )

            allow = response.headers.get("Allow", "")
            if not allow:
                return

            allowed_methods = [m.strip().upper() for m in allow.split(",")]
            logger.info(f"🔧 OPTIONS {target.url} → Allow: {allow}")

            for method in allowed_methods:
                if method in DANGEROUS_METHODS:
                    desc, sev = DANGEROUS_METHODS[method]
                    vulns.append(Vulnerability(
                        name=f"Dangerous HTTP Method: {method}",
                        description=(
                            f"El servidor anuncia que el método {method} está habilitado. "
                            f"{desc}"
                        ),
                        severity=sev,
                        target_url=target.url,
                        payload=f"OPTIONS → Allow: {allow}"
                    ))

        except requests.RequestException as e:
            logger.debug(f"Error en OPTIONS: {e}")

    def _probe_methods(self, target, vulns):
        """Prueba directamente métodos peligrosos y verifica la respuesta."""
        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}

            # Solo probar TRACE directamente (es el más revelador)
            response = requests.request(
                "TRACE", target.url, headers=headers, timeout=5, verify=False
            )

            # Si TRACE responde 200 y refleja la petición → XST vulnerable
            if response.status_code == 200 and "TRACE" in response.text.upper():
                # Evitar duplicado si ya lo reportó OPTIONS
                already_reported = any(
                    v.name == "Dangerous HTTP Method: TRACE" for v in vulns
                )
                if not already_reported:
                    vulns.append(Vulnerability(
                        name="TRACE Method Active (XST)",
                        description=(
                            "El servidor responde a peticiones TRACE reflejando el "
                            "contenido. Esto habilita ataques Cross-Site Tracing "
                            "para robar cookies HttpOnly vía JavaScript."
                        ),
                        severity=Severity.HIGH,
                        target_url=target.url,
                        payload=f"TRACE {target.url} → HTTP 200"
                    ))

        except requests.RequestException as e:
            logger.debug(f"Error probando TRACE: {e}")
