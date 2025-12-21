from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability, Severity


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
        # Hago como que pienso...
        print(f"    [Dummy] Fingiendo que analizo {target.url} intensamente...")

        # Me invento una vulnerabilidad para ver si el reporte la agarra.
        vuln = Vulnerability(
            name="Vulnerabilidad de Mentira",
            severity=Severity.INFO,
            description="Si ves esto, es que el sistema de módulos funciona.",
            target_url=target.url,
            evidence="<script>alert('Test')</script>"
        )

        # Devuelvo una lista porque así lo exige el contrato (type hint list[Vulnerability]).
        return [vuln]