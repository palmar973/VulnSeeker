import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.models import ScannerModule, Target, Vulnerability, Severity

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
        Soporta tanto query params en la URL como formularios GET.
        """
        vulnerabilities: list[Vulnerability] = []

        parsed_url = urlparse(target.url)
        query_params = parse_qs(parsed_url.query)

        if query_params:
            logger.info(f"Analizando XSS en: {target.url}")
            self._fuzz_params(parsed_url, query_params, target.headers, vulnerabilities)

        # Formularios GET: construir URL con params del form y fuzzear
        for element in target.elements:
            if element.is_form and element.method.upper() == "GET" and element.params:
                logger.info(f"Analizando XSS (GET form) en: {element.url}")
                form_parsed = urlparse(element.url)
                form_query_params = {k: [v] for k, v in element.params.items()}
                self._fuzz_params(form_parsed, form_query_params, target.headers, vulnerabilities)

        return vulnerabilities

    def _fuzz_params(self, parsed_url, query_params, headers, vulnerabilities):
        """Inyecta el payload canario en cada parámetro y verifica si se refleja sin sanitizar."""
        xss_payload: str = "<VulnSeekerXSS>"

        for param_name in query_params.keys():
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
                req_headers = headers or {'User-Agent': 'VulnSeeker/1.0'}
                response = requests.get(malicious_url, headers=req_headers, timeout=5, verify=False)

                # Si sanitiza, debería volver escapado; si regresa intacto es reflejado.
                if xss_payload in response.text:
                    logger.warning(f"  [!!!] XSS Reflejado detectado en parámetro '{param_name}'")

                    vuln = Vulnerability(
                        name="Reflected Cross-Site Scripting (XSS)",
                        severity=Severity.MEDIUM,
                        description=f"El parámetro '{param_name}' refleja la entrada del usuario sin filtrar caracteres HTML.",
                        target_url=malicious_url,
                        evidence=f"Payload inyectado: {xss_payload} encontrado en la respuesta."
                    )
                    vulnerabilities.append(vuln)

            except requests.RequestException as e:
                logger.debug(f"Error de conexión probando XSS: {e}")
