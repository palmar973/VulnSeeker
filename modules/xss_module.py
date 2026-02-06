import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.scanner_types import ScannerModule, Target, Vulnerability, Severity

logger = logging.getLogger(__name__)


class XSSScanner(ScannerModule):
    """
    Módulo especializado en la detección de Reflected Cross-Site Scripting (XSS).
    """

    @property
    def name(self) -> str:
        return "Reflected XSS Module"

    @property
    def description(self) -> str:
        return "Detecta si los parámetros de entrada se reflejan en la respuesta sin sanitización."

    def run(self, target: Target) -> list[Vulnerability]:
        """
        Inyecta un payload inofensivo (Canario) y verifica si regresa en el HTML.
        """
        vulnerabilities: list[Vulnerability] = []

        parsed_url = urlparse(target.url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            logger.debug(f"Saltando {target.url} (Sin parámetros para XSS).")
            return []

        logger.info(f"Analizando XSS en: {target.url}")

        # Payload canario fácil de rastrear
        xss_payload: str = "<VulnSeekerXSS>"

        for param_name in query_params.keys():
            original_values = query_params[param_name]

            fuzzed_params = query_params.copy()
            fuzzed_params[param_name] = [xss_payload]

            new_query = urlencode(fuzzed_params, doseq=True)
            malicious_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))

            try:
                headers = target.headers or {'User-Agent': 'VulnSeeker/1.0'}
                response = requests.get(malicious_url, headers=headers, timeout=5)

                # Si sanitiza, debería volver escapado; si regresa intacto es reflejado.
                if xss_payload in response.text:
                    logger.warning(f"  [!!!] XSS Reflejado detectado en parámetro '{param_name}'")

                    vuln = Vulnerability(
                        name="Reflected Cross-Site Scripting (XSS)",
                        severity=Severity.MEDIUM,  # XSS suele ser Medium/High dependiendo del impacto.
                        description=f"El parámetro '{param_name}' refleja la entrada del usuario sin filtrar caracteres HTML.",
                        target_url=malicious_url,  # Guardo la URL maliciosa como prueba
                        evidence=f"Payload inyectado: {xss_payload} encontrado en la respuesta."
                    )
                    vulnerabilities.append(vuln)

            except requests.RequestException as e:
                logger.debug(f"Error de conexión probando XSS: {e}")

        return vulnerabilities