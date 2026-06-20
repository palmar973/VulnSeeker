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
                    # Timeout corto porque las conexiones externas pueden tardar
                    resp = session.get(attack_url, headers=headers, timeout=5, verify=False)

                    # Verificación: ¿El contenido del archivo remoto apareció en la respuesta?
                    if keyword in resp.text:
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
