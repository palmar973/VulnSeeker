import logging
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.models import ScannerModule, Target, Vulnerability, Severity

logger = logging.getLogger(__name__)


class SQLInjectionScanner(ScannerModule):
    """
    Módulo especializado en la detección de SQL Injection (SQLi)
    basado en errores (Error-Based SQLi).

    Soporta fuzzing sobre parámetros GET (query string) y POST (form body).
    Emplea doble estrategia de mutación: concatenación y reemplazo completo.
    """

    # Payloads clásicos para forzar errores de sintaxis visibles.
    # Se incluyen variantes que rompen estructuras con paréntesis/UNION, habituales
    # en APIs REST (p. ej. el buscador de OWASP Juice Shop sobre SQLite).
    PAYLOADS: list[str] = [
        "'", '"', "';", "--", "' OR '1'='1",
        "'))--", "')) OR 1=1-- -", "' UNION SELECT NULL-- -",
    ]

    # Firmas de error comunes de motores SQL (MySQL, PostgreSQL, Oracle, MSSQL y SQLite).
    ERROR_SIGNATURES: list[str] = [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "Unclosed quotation mark after the character string",
        "ORA-00933: SQL command not properly ended",
        "PostgreSQL query failed",
        "microsoft sql native client error",
        "org.postgresql.util.PSQLException",
        "com.mysql.jdbc.exceptions",
        # SQLite (común en APIs Node/Express como Juice Shop)
        "SQLITE_ERROR",
        "SQLITE_CONSTRAINT",
        "sqlite3.OperationalError",
        "unrecognized token",
        "SQL error or missing database",
        # ORMs que filtran el error SQL en su stack trace (Sequelize sobre SQLite, etc.)
        "SequelizeDatabaseError",
        "sequelize/lib/dialects",
        # Java/JDBC: cualquier backend accedido vía JDBC (HSQLDB, MySQL, Oracle, etc.)
        # propaga estas excepciones cuando el servidor no maneja el error SQL.
        # Es el motor del OWASP Benchmark (HSQLDB sobre Tomcat).
        "java.sql.SQLException",
        "java.sql.SQLSyntaxErrorException",
        "org.hsqldb",
    ]

    # Payloads para SQLi ciego basado en tiempo ({d} = retardo en segundos).
    # Cubren MySQL/MariaDB (SLEEP), MSSQL (WAITFOR) y PostgreSQL (pg_sleep).
    TIME_DELAY: int = 3
    TIME_PAYLOADS: list[str] = [
        "' AND SLEEP({d})-- -",
        "\" AND SLEEP({d})-- -",
        "' OR SLEEP({d})-- -",
        "1' AND SLEEP({d})-- -",
        "'; WAITFOR DELAY '0:0:{d}'-- -",
        "'; SELECT pg_sleep({d})-- -",
    ]

    def __init__(self, enable_blind: bool = True) -> None:
        # SQLi ciego (time-based) activable. Solo añade latencia real en
        # parámetros verdaderamente vulnerables; los demás responden de inmediato.
        self.enable_blind = enable_blind

    @property
    def name(self) -> str:
        return "SQL Injection Module (Error-Based)"

    @property
    def description(self) -> str:
        return ("Detecta SQLi basada en errores (inyección de caracteres especiales) y "
                "SQLi ciega basada en tiempo (retardos controlados con confirmación proporcional).")

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
        # Estrategia 3: Formularios GET (params como query string, no en la URL base)
        # Estrategia 3.5: Cuerpos JSON de APIs REST (SPAs / servicios)
        for element in target.elements:
            if getattr(element, "body_type", "form") == "json" and element.params:
                logger.info(f"SQLi Scanner: Fuzzing JSON body en {element.url}")
                self._fuzz_json_params(target, element, vulnerabilities)
            elif element.is_form and element.method.upper() == "POST" and element.params:
                logger.info(f"SQLi Scanner: Fuzzing POST params en {element.url}")
                self._fuzz_post_params(target, element, vulnerabilities)
            elif element.is_form and element.method.upper() == "GET" and element.params:
                logger.info(f"SQLi Scanner: Fuzzing GET form params en {element.url}")
                self._fuzz_get_form_params(target, element, vulnerabilities)

        # Estrategia 4: SQLi ciego basado en tiempo (Blind Time-Based).
        # Actúa como complemento del error-based: solo se evalúan los parámetros
        # cuya URL no fue ya marcada, evitando duplicar hallazgos y costo.
        if self.enable_blind:
            self._run_blind_time(target, query_params, vulnerabilities)

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

    def _fuzz_get_form_params(self, target, element, vulnerabilities):
        """Inyecta payloads en formularios con método GET construyendo la URL con query string."""
        parsed_url = urlparse(element.url)

        for param_name in element.params.keys():
            original_value = element.params.get(param_name, "")

            for payload in self.PAYLOADS:
                mutations = [
                    original_value + payload,
                    payload,
                ]

                for mutated_value in mutations:
                    fuzzed_params = dict(element.params)
                    fuzzed_params[param_name] = mutated_value
                    new_query = urlencode(fuzzed_params)
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
                        target_url=element.url,
                        vulnerabilities=vulnerabilities
                    )
                    if found:
                        break
                else:
                    continue
                break

    def _fuzz_json_params(self, target, element, vulnerabilities):
        """Inyecta payloads en cada campo de un cuerpo JSON (endpoints de API REST).
        Es el equivalente de _fuzz_post_params pero con Content-Type application/json,
        necesario para SPAs/servicios que reciben los datos como JSON (p. ej. el login
        de OWASP Juice Shop: POST /rest/user/login {email, password})."""
        headers = dict(target.headers or {})
        headers["Content-Type"] = "application/json"

        for param_name in element.params.keys():
            original_value = element.params.get(param_name, "")

            for payload in self.PAYLOADS:
                mutations = [
                    str(original_value) + payload,
                    payload,
                ]

                for mutated_value in mutations:
                    fuzzed_body = dict(element.params)
                    fuzzed_body[param_name] = mutated_value

                    found = self._send_and_check_json(
                        url=element.url,
                        headers=headers,
                        json_body=fuzzed_body,
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

    def _send_and_check_json(self, url, headers, json_body, param_name, payload,
                             target_url, vulnerabilities) -> bool:
        """Envía un POST con cuerpo JSON y busca firmas de error SQL en la respuesta."""
        try:
            response = requests.post(url, json=json_body, headers=headers, timeout=5, verify=False)

            for error in self.ERROR_SIGNATURES:
                if error.lower() in response.text.lower():
                    logger.warning(
                        f"  [!!!] Posible SQLi (JSON) en '{param_name}' con payload: {payload}"
                    )
                    vulnerabilities.append(Vulnerability(
                        name="SQL Injection (Error Based - JSON)",
                        severity=Severity.HIGH,
                        description=(
                            f"Se detectó un error de BD al inyectar en el campo JSON "
                            f"'{param_name}' de un endpoint de API REST."
                        ),
                        target_url=target_url,
                        evidence=f"Payload: {payload} | Error: {error}"
                    ))
                    return True

        except requests.RequestException as e:
            logger.debug(f"Error de conexión probando payload JSON: {e}")

        return False

    def _send_and_check(self, method, url, headers, param_name, payload,
                        target_url, vulnerabilities, data=None) -> bool:
        """Envía la petición y busca firmas de error SQL en la respuesta."""
        try:
            headers = headers or {'User-Agent': 'VulnSeeker/1.0'}

            if method == "POST":
                response = requests.post(url, data=data, headers=headers, timeout=5, verify=False)
            else:
                response = requests.get(url, headers=headers, timeout=5, verify=False)

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

    # ------------------------------------------------------------------
    # SQLi ciego basado en tiempo (Blind Time-Based)
    # ------------------------------------------------------------------
    def _run_blind_time(self, target, query_params, vulnerabilities):
        """Aplica la detección time-based a los parámetros (query y formularios)
        cuya URL no fue ya marcada por la detección basada en errores."""
        urls_con_error = {v.target_url for v in vulnerabilities}

        if query_params and target.url not in urls_con_error:
            base = {k: v[0] for k, v in query_params.items()}
            self._blind_check(target, "GET", target.url, base, vulnerabilities)

        for element in target.elements:
            if element.is_form and element.params and element.url not in urls_con_error:
                self._blind_check(target, element.method.upper(), element.url,
                                  dict(element.params), vulnerabilities)

    def _blind_check(self, target, method, url, base_params, vulnerabilities):
        """Mide la latencia diferencial: si inyectar un retardo controlado demora
        la respuesta de forma proporcional, el parámetro es vulnerable a SQLi ciego."""
        headers = target.headers or {'User-Agent': 'VulnSeeker/1.0'}
        parsed = urlparse(url)

        for param_name in list(base_params.keys()):
            original = base_params.get(param_name, "")

            t_base = self._timed_inject(method, parsed, param_name, original, base_params, headers)
            if t_base is None:
                continue

            for tmpl in self.TIME_PAYLOADS:
                payload = f"{original}{tmpl.format(d=self.TIME_DELAY)}"
                t1 = self._timed_inject(method, parsed, param_name, payload, base_params, headers)
                if t1 is None or t1 < t_base + self.TIME_DELAY * 0.7:
                    continue

                # Confirmación anti-falsos-positivos: el retardo debe escalar al
                # duplicar el SLEEP. Esto descarta lentitudes puntuales de red.
                payload2 = f"{original}{tmpl.format(d=self.TIME_DELAY * 2)}"
                t2 = self._timed_inject(method, parsed, param_name, payload2, base_params, headers)
                if t2 is not None and t2 >= t_base + self.TIME_DELAY * 2 * 0.7:
                    logger.warning(f"  [!!!] Blind SQLi (time-based) en '{param_name}' ({method})")
                    vulnerabilities.append(Vulnerability(
                        name="SQL Injection (Blind Time-Based)",
                        severity=Severity.HIGH,
                        description=(
                            f"El parámetro '{param_name}' es vulnerable a SQLi ciego basado "
                            f"en tiempo vía {method}: la inyección de retardos controlados "
                            f"({self.TIME_DELAY}s y {self.TIME_DELAY * 2}s) produjo demoras "
                            f"proporcionales en la respuesta."
                        ),
                        target_url=url,
                        evidence=(
                            f"Baseline {t_base:.2f}s | SLEEP({self.TIME_DELAY})->{t1:.2f}s | "
                            f"SLEEP({self.TIME_DELAY * 2})->{t2:.2f}s"
                        ),
                        payload=payload,
                    ))
                    break  # un hallazgo por parámetro

    def _timed_inject(self, method, parsed_url, param_name, value, base_params, headers):
        """Inyecta 'value' en 'param_name' y devuelve el tiempo de respuesta en
        segundos (None si la petición falla)."""
        fuzzed = dict(base_params)
        fuzzed[param_name] = value
        timeout = self.TIME_DELAY * 2 + 5
        try:
            start = time.perf_counter()
            if method == "POST":
                post_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                       parsed_url.params, "", parsed_url.fragment))
                requests.post(post_url, data=fuzzed, headers=headers, timeout=timeout, verify=False)
            else:
                query = urlencode(fuzzed)
                get_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                      parsed_url.params, query, parsed_url.fragment))
                requests.get(get_url, headers=headers, timeout=timeout, verify=False)
            return time.perf_counter() - start
        except Exception:
            return None
