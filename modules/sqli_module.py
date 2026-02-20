import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.scanner_types import ScannerModule, Target, Vulnerability, Severity

logger = logging.getLogger(__name__)


class SQLInjectionScanner(ScannerModule):
    """
    Módulo especializado en la detección de SQL Injection (SQLi)
    basado en errores (Error-Based SQLi).

    Soporta fuzzing sobre parámetros GET (query string) y POST (form body).
    Emplea doble estrategia de mutación: concatenación y reemplazo completo.
    """

    # Payloads clásicos para forzar errores de sintaxis visibles
    PAYLOADS: list[str] = ["'", '"', "';", "--", "' OR '1'='1"]

    # Firmas de error comunes de motores SQL
    ERROR_SIGNATURES: list[str] = [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "Unclosed quotation mark after the character string",
        "ORA-00933: SQL command not properly ended",
        "PostgreSQL query failed",
        "microsoft sql native client error",
        "org.postgresql.util.PSQLException",
        "com.mysql.jdbc.exceptions",
    ]

    @property
    def name(self) -> str:
        return "SQL Injection Module (Error-Based)"

    @property
    def description(self) -> str:
        return "Detecta vulnerabilidades SQLi inyectando caracteres especiales y buscando errores de BD."

    def run(self, target: Target) -> list[Vulnerability]:
        """Analiza parámetros GET y POST para disparar errores SQL visibles."""
        vulnerabilities: list[Vulnerability] = []

        # Estrategia 1: Parámetros GET en la URL (query string)
        parsed_url = urlparse(target.url)
        query_params = parse_qs(parsed_url.query)

        if query_params:
            logger.info(f"SQLi Scanner: Fuzzing GET params en {target.url}")
            self._fuzz_get_params(target, parsed_url, query_params, vulnerabilities)

        # Estrategia 2: Parámetros POST desde formularios
        for element in target.elements:
            if element.is_form and element.method.upper() == "POST" and element.params:
                logger.info(f"SQLi Scanner: Fuzzing POST params en {element.url}")
                self._fuzz_post_params(target, element, vulnerabilities)

        return vulnerabilities

    def _fuzz_get_params(self, target, parsed_url, query_params, vulnerabilities):
        """Inyecta payloads en parámetros de la query string (GET)."""
        for param_name in query_params.keys():
            original_value = query_params[param_name][0]

            for payload in self.PAYLOADS:
                # Doble estrategia: concatenar al valor original Y reemplazar completo
                mutations = [
                    original_value + payload,  # Concatenación: id=5'
                    payload,                   # Reemplazo:     id='
                ]

                for mutated_value in mutations:
                    fuzzed_params = query_params.copy()
                    fuzzed_params[param_name] = [mutated_value]
                    new_query = urlencode(fuzzed_params, doseq=True)
                    malicious_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))

                    found = self._send_and_check(
                        method="GET",
                        url=malicious_url,
                        headers=target.headers,
                        param_name=param_name,
                        payload=mutated_value,
                        target_url=target.url,
                        vulnerabilities=vulnerabilities
                    )
                    if found:
                        break  # Evitar reportar mismo parámetro varias veces
                else:
                    continue
                break

    def _fuzz_post_params(self, target, element, vulnerabilities):
        """Inyecta payloads en parámetros del body (POST forms)."""
        for param_name in element.params.keys():
            original_value = element.params.get(param_name, "")

            for payload in self.PAYLOADS:
                mutations = [
                    original_value + payload,
                    payload,
                ]

                for mutated_value in mutations:
                    fuzzed_data = dict(element.params)
                    fuzzed_data[param_name] = mutated_value

                    found = self._send_and_check(
                        method="POST",
                        url=element.url,
                        headers=target.headers,
                        data=fuzzed_data,
                        param_name=param_name,
                        payload=mutated_value,
                        target_url=element.url,
                        vulnerabilities=vulnerabilities
                    )
                    if found:
                        break
                else:
                    continue
                break

    def _send_and_check(self, method, url, headers, param_name, payload,
                        target_url, vulnerabilities, data=None) -> bool:
        """Envía la petición y busca firmas de error SQL en la respuesta."""
        try:
            headers = headers or {'User-Agent': 'VulnSeeker/1.0'}

            if method == "POST":
                response = requests.post(url, data=data, headers=headers, timeout=5)
            else:
                response = requests.get(url, headers=headers, timeout=5)

            for error in self.ERROR_SIGNATURES:
                if error.lower() in response.text.lower():
                    logger.warning(
                        f"  [!!!] Posible SQLi ({method}) en '{param_name}' con payload: {payload}"
                    )
                    vulnerabilities.append(Vulnerability(
                        name=f"SQL Injection (Error Based - {method})",
                        severity=Severity.HIGH,
                        description=(
                            f"Se detectó un error de BD al inyectar en el parámetro "
                            f"'{param_name}' vía {method}."
                        ),
                        target_url=target_url,
                        evidence=f"Payload: {payload} | Error: {error}"
                    ))
                    return True

        except requests.RequestException as e:
            logger.debug(f"Error de conexión probando payload: {e}")

        return False