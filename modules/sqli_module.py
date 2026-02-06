import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.scanner_types import ScannerModule, Target, Vulnerability, Severity

logger = logging.getLogger(__name__)


class SQLInjectionScanner(ScannerModule):
    """
    Módulo especializado en la detección de SQL Injection (SQLi)
    basado en errores (Error-Based SQLi).
    """

    @property
    def name(self) -> str:
        return "SQL Injection Module (Error-Based)"

    @property
    def description(self) -> str:
        return "Detecta vulnerabilidades SQLi inyectando caracteres especiales y buscando errores de BD."

    def run(self, target: Target) -> list[Vulnerability]:
        """Analiza parámetros GET e intenta disparar errores SQL visibles."""
        vulnerabilities: list[Vulnerability] = []

        parsed_url = urlparse(target.url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            logger.debug(f"Saltando {target.url} (Sin parámetros para inyectar).")
            return []

        logger.info(f"Analizando parámetros en: {target.url}")

        # Payloads clásicos para forzar errores de sintaxis visibles
        payloads: list[str] = ["'", '"', "';", "--", "' OR '1'='1"]

        # Firmas de error comunes de motores SQL
        error_signatures: list[str] = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "Unclosed quotation mark after the character string",
            "ORA-00933: SQL command not properly ended",
            "PostgreSQL query failed"
        ]

        for param_name in query_params.keys():
            original_values = query_params[param_name]

            for payload in payloads:
                fuzzed_params = query_params.copy()
                fuzzed_params[param_name] = [original_values[0] + payload]
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

                    for error in error_signatures:
                        if error in response.text:
                            logger.warning(f"  [!!!] Posible SQLi en parámetro '{param_name}' con payload: {payload}")

                            vuln = Vulnerability(
                                name="SQL Injection (Error Based)",
                                severity=Severity.HIGH,  # SQLi siempre es grave.
                                description=f"Se detectó un error de base de datos al inyectar en el parámetro '{param_name}'.",
                                target_url=target.url,
                                evidence=f"Payload: {payload} | Error detectado: {error}"
                            )
                            vulnerabilities.append(vuln)

                            # Evito reportar el mismo parámetro varias veces
                            break

                except requests.RequestException as e:
                    logger.debug(f"Error de conexión probando payload: {e}")


        return vulnerabilities