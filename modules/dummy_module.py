from core.models import ScannerModule, Target, Vulnerability, Severity
import logging


class DummyScanner(ScannerModule):
    """
    Módulo tonto para probar que el Engine funciona.
    """

    @property
    def name(self) -> str:
        return "Dummy Test Module"

    @property
    def description(self) -> str:
        return "Solo existo para validar que la arquitectura no está rota."

    def run(self, target: Target) -> list[Vulnerability]:
        logging.info(f"🔍 DEBUG CONTEXT: {target.context}")
        print(f"    [Dummy] Fingiendo que analizo {target.url} intensamente...")

        vuln = Vulnerability(
            name="Vulnerabilidad de Mentira",
            severity=Severity.INFO,
            description="Si ves esto, es que el sistema de módulos funciona.",
            target_url=target.url,
            evidence="<script>alert('Test')</script>"
        )

        return [vuln]