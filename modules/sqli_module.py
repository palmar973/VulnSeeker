import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability, Severity

# Logger específico para este módulo
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
        """
        Analiza la URL en busca de parámetros GET e intenta inyectar payloads.
        """
        vulnerabilities: list[Vulnerability] = []

        # 1. Analizo si la URL tiene parámetros. Si es estática, no pierdo tiempo.
        parsed_url = urlparse(target.url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            logger.debug(f"Saltando {target.url} (Sin parámetros para inyectar).")
            return []

        logger.info(f"Analizando parámetros en: {target.url}")

        # Lista de 'venenos' para ver si la base de datos se queja.
        # Para la tesis, usamos payloads clásicos que provocan errores de sintaxis.
        payloads: list[str] = ["'", '"', "';", "--", "' OR '1'='1"]

        # Firmas de error comunes en Motores de Base de Datos.
        # Si encuentro esto en el HTML, es BINGO.
        error_signatures: list[str] = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "Unclosed quotation mark after the character string",
            "ORA-00933: SQL command not properly ended",
            "PostgreSQL query failed"
        ]

        # 2. Itero sobre cada parámetro (ej: id=1, cat=book)
        for param_name in query_params.keys():
            # Guardo el valor original para restaurarlo después.
            original_values = query_params[param_name]  # Esto es una lista

            for payload in payloads:
                # Construyo la URL maliciosa.
                # Copio los params para no modificar el diccionario original del bucle.
                fuzzed_params = query_params.copy()

                # Inyecto el payload en el primer valor del parámetro.
                fuzzed_params[param_name] = [original_values[0] + payload]

                # Reconstruyo la URL completa con el veneno.
                new_query = urlencode(fuzzed_params, doseq=True)
                malicious_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))

                # 3. Disparo la petición
                try:
                    # Uso los headers del target si existen, o unos default.
                    headers = target.headers or {'User-Agent': 'VulnSeeker/1.0'}
                    response = requests.get(malicious_url, headers=headers, timeout=5)

                    # 4. Análisis de la respuesta (Pattern Matching)
                    for error in error_signatures:
                        if error in response.text:
                            # ¡Encontré algo!
                            logger.warning(f"  [!!!] Posible SQLi en parámetro '{param_name}' con payload: {payload}")

                            vuln = Vulnerability(
                                name="SQL Injection (Error Based)",
                                severity=Severity.HIGH,  # SQLi siempre es grave.
                                description=f"Se detectó un error de base de datos al inyectar en el parámetro '{param_name}'.",
                                target_url=target.url,
                                evidence=f"Payload: {payload} | Error detectado: {error}"
                            )
                            vulnerabilities.append(vuln)

                            # Si ya encontré que este parámetro es vulnerable,
                            # rompo el ciclo de payloads para no reportar lo mismo 5 veces.
                            break

                except requests.RequestException as e:
                    logger.debug(f"Error de conexión probando payload: {e}")

            # Si encontré vulnerabilidad en este parámetro, paso al siguiente parámetro (opcional, decisión de diseño).
            # Por ahora dejo que siga probando otros parámetros.

        return vulnerabilities