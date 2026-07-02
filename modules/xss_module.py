import logging

from core.models import ScannerModule, Target, Vulnerability, Severity
from modules.injection_points import collect_points

logger = logging.getLogger(__name__)


class XSSScanner(ScannerModule):
    """
    Módulo especializado en la detección de Reflected Cross-Site Scripting (XSS).

    Inyecta un canario inofensivo (``<VulnSeekerXSS>``) en cada punto de inyección
    del objetivo (GET query, POST form y GET form, vía :func:`collect_points`) y
    reporta si regresa sin sanitizar en la respuesta. Se omite el vector JSON: que
    el canario se refleje en un cuerpo ``application/json`` no implica ejecución en
    un contexto HTML, así que reportarlo sería un falso positivo.
    """

    CANARY = "<VulnSeekerXSS>"

    @property
    def name(self) -> str:
        return "Reflected XSS Module"

    @property
    def description(self) -> str:
        return "Detecta si los parámetros de entrada se reflejan en la respuesta sin sanitización."

    def run(self, target: Target) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        headers = target.headers or {'User-Agent': 'VulnSeeker/1.0'}

        for pt in collect_points(target):
            if pt.body_type == "json":
                continue  # reflejar el canario en JSON no es XSS (contexto no HTML)

            response = pt.send(self.CANARY, headers=headers)
            if response is None:
                continue

            # Si sanitiza, el canario vuelve escapado (&lt;…&gt;); si regresa intacto
            # es reflejado y explotable.
            if self.CANARY in response.text:
                logger.warning(f"  [!!!] XSS Reflejado detectado en parámetro '{pt.param_name}' ({pt.method})")
                vulnerabilities.append(Vulnerability(
                    name="Reflected Cross-Site Scripting (XSS)",
                    severity=Severity.MEDIUM,
                    description=(f"El parámetro '{pt.param_name}' ({pt.method}) refleja la entrada "
                                 f"del usuario sin filtrar caracteres HTML."),
                    target_url=pt.report_url,
                    evidence=f"Payload inyectado: {self.CANARY} encontrado en la respuesta.",
                ))

        return vulnerabilities
