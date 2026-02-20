import logging
import requests
from bs4 import BeautifulSoup
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.FileUpload")

# Extensiones peligrosas que no deberían ser aceptadas sin restricción
DANGEROUS_EXTENSIONS = [
    ".php", ".phtml", ".php5", ".php7",
    ".asp", ".aspx", ".jsp", ".jspx",
    ".exe", ".bat", ".cmd", ".sh",
    ".py", ".pl", ".rb", ".cgi",
    ".svg", ".html", ".htm", ".shtml",
]


class FileUploadDetector(ScannerModule):
    """Detecta formularios de subida de archivos sin restricciones (OWASP A04)."""

    @property
    def name(self) -> str:
        return "File Upload Detector"

    @property
    def description(self) -> str:
        return "Identifica formularios con subida de archivos sin validación de tipos."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            response = requests.get(target.url, headers=headers, timeout=5)

            if "text/html" not in response.headers.get("Content-Type", ""):
                return vulns

            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                file_inputs = form.find_all("input", {"type": "file"})

                if not file_inputs:
                    continue

                # Hay un input type=file → analizar restricciones
                form_action = form.get("action", target.url)
                form_method = form.get("method", "GET").upper()
                enctype = form.get("enctype", "")

                for file_input in file_inputs:
                    input_name = file_input.get("name", "unknown")
                    accept_attr = file_input.get("accept", "")

                    # Check 1: ¿Tiene atributo accept?
                    if not accept_attr:
                        vulns.append(Vulnerability(
                            name="Unrestricted File Upload",
                            description=(
                                f"El formulario tiene un campo de subida de archivos "
                                f"'{input_name}' sin restricción de tipos (sin atributo accept). "
                                f"Un atacante podría subir archivos maliciosos como web shells."
                            ),
                            severity=Severity.HIGH,
                            target_url=target.url,
                            payload=f"{form_method} {form_action} (campo: {input_name})"
                        ))
                    else:
                        # Check 2: ¿Acepta tipos peligrosos?
                        accepted = [a.strip().lower() for a in accept_attr.split(",")]
                        dangerous_accepted = [
                            ext for ext in DANGEROUS_EXTENSIONS
                            if ext in accepted or f"*/*" in accepted
                        ]

                        if dangerous_accepted:
                            vulns.append(Vulnerability(
                                name="Dangerous File Types Accepted",
                                description=(
                                    f"El campo '{input_name}' acepta tipos de archivo peligrosos: "
                                    f"{', '.join(dangerous_accepted)}. "
                                    f"Esto podría permitir la subida de web shells o ejecutables."
                                ),
                                severity=Severity.HIGH,
                                target_url=target.url,
                                payload=f"accept=\"{accept_attr}\""
                            ))

                    # Check 3: ¿Usa enctype correcto para multipart?
                    if form_method == "POST" and enctype != "multipart/form-data":
                        vulns.append(Vulnerability(
                            name="File Upload Missing Multipart",
                            description=(
                                f"El formulario con campo de archivo '{input_name}' no usa "
                                f"enctype='multipart/form-data'. Esto puede indicar un "
                                f"procesamiento inseguro del archivo en el servidor."
                            ),
                            severity=Severity.LOW,
                            target_url=target.url,
                            payload=f"enctype=\"{enctype or 'no especificado'}\""
                        ))

        except requests.RequestException as e:
            logger.debug(f"Error de conexión: {e}")
        except Exception as e:
            logger.error(f"Error en FileUploadDetector: {e}")

        return vulns
