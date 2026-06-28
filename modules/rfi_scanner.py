import requests
import logging
import re
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.RFIScanner")


class RFIScanner(ScannerModule):
    """
    Escáner de Remote File Inclusion (RFI).
    Intenta inyectar URLs remotas para ver si el servidor las carga.
    """

    @property
    def name(self) -> str:
        return "Remote File Inclusion (RFI)"

    @property
    def description(self) -> str:
        return "Detecta si la aplicación permite incluir y ejecutar archivos desde servidores remotos."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns = []

        # Payloads ligeros y confiables para validar inclusión remota
        payloads = [
            ("http://www.google.com/robots.txt", "User-agent:"),
            ("https://www.google.com/robots.txt", "User-agent:"),
            ("http://example.com/", "Example Domain")
        ]

        # Parámetros sospechosos comunes donde suele ocurrir RFI
        suspicious_params = ['page', 'file', 'doc', 'document', 'url', 'path', 'include', 'template']

        params_to_test = []
        if "?" in target.url:
            try:
                query_string = target.url.split("?")[1]
                for pair in query_string.split("&"):
                    if "=" in pair:
                        key = pair.split("=")[0]
                        params_to_test.append(key)
            except:
                pass

        if not params_to_test:
            params_to_test = suspicious_params

        logger.info(f"🌍 RFI Scanner: Probando {len(params_to_test)} parámetros en {target.url}")

        headers = {'User-Agent': 'VulnSeeker/1.0'}
        if target.headers:
            headers.update(target.headers)

        # Usamos sesión para velocidad
        session = requests.Session()

        # Obtener respuesta baseline
        baseline_text = ""
        try:
            resp_base = session.get(target.url, headers=headers, timeout=5, verify=False,
                                    allow_redirects=False)
            baseline_text = resp_base.text
        except Exception:
            pass

        for param in params_to_test:
            for payload_url, keyword in payloads:
                # Construir URL de ataque
                # Si la URL original ya tenía parámetros, tratamos de reemplazarlos o añadir
                if "?" in target.url:
                    # Estrategia simple: Reemplazar valor del parámetro si existe, o añadirlo
                    if param in target.url:
                        # Reemplaza param=loquesea por param=payload
                        attack_url = re.sub(f"{param}=[^&]*", f"{param}={payload_url}", target.url)
                    else:
                        attack_url = f"{target.url}&{param}={payload_url}"
                else:
                    attack_url = f"{target.url}?{param}={payload_url}"

                try:
                    # Timeout corto porque las conexiones externas pueden tardar.
                    # allow_redirects=False evita confundir un Open Redirect (302 hacia la
                    # URL del payload) con una inclusión remota real: solo es RFI si el
                    # servidor INCLUYE el contenido remoto en la respuesta (200), no si
                    # simplemente redirige hacia él.
                    resp = session.get(attack_url, headers=headers, timeout=5, verify=False,
                                       allow_redirects=False)

                    # Verificación: ¿El contenido del archivo remoto apareció en la respuesta
                    # y NO estaba ya en el baseline (descarta falsos positivos pre-existentes)?
                    if keyword in resp.text and keyword not in baseline_text:
                        desc = (f"Se detectó vulnerabilidad RFI (Remote File Inclusion).\n"
                                f"El servidor descargó e incluyó contenido desde: {payload_url}\n"
                                f"Parámetro vulnerable: {param}")

                        v = Vulnerability(
                            name="Remote File Inclusion (RFI)",
                            severity=Severity.CRITICAL,  # RFI suele ser CRÍTICO (RCE potencial)
                            description=desc,
                            target_url=target.url,
                            evidence=f"Payload: {payload_url} | Found keyword: '{keyword}' in response.",
                            payload=attack_url
                        )
                        vulns.append(v)
                        logger.info(f"🔥 ¡RFI DETECTADO! {attack_url}")

                        # Si encontramos una, generalmente basta por parámetro
                        break

                except Exception:
                    pass

        return vulns
