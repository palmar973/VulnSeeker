"""
Tests unitarios: Motor VulnSeeker (engine.py).
Valida registro de módulos, reset de resultados y flujo de escaneo.
"""
from unittest.mock import patch, MagicMock
from core.engine import VulnSeekerEngine
from core.models import ScannerModule, Target, Vulnerability, Severity, PageElement


class FakeModule(ScannerModule):
    """Módulo falso para tests."""
    @property
    def name(self) -> str:
        return "FakeModule"

    @property
    def description(self) -> str:
        return "Módulo de prueba"

    def run(self, target: Target) -> list[Vulnerability]:
        return [Vulnerability(
            name="FakeVuln",
            severity=Severity.INFO,
            description="Vulnerabilidad de prueba",
            target_url=target.url
        )]


def test_registrar_modulo_valido():
    """El engine debe aceptar módulos que hereden de ScannerModule."""
    engine = VulnSeekerEngine(enable_subdomains=False)
    engine.register_module(FakeModule())
    assert len(engine.modules) == 1
    assert engine.modules[0].name == "FakeModule"


def test_registrar_objeto_invalido_lanza_error():
    """Registrar algo que no sea ScannerModule debe lanzar TypeError."""
    engine = VulnSeekerEngine(enable_subdomains=False)
    try:
        engine.register_module("no soy un módulo")
        assert False, "Debería haber lanzado TypeError"
    except TypeError:
        pass


def test_results_se_resetean_entre_scans():
    """Llamar scan() dos veces no debe acumular resultados del scan anterior."""
    engine = VulnSeekerEngine(enable_subdomains=False)
    engine.register_module(FakeModule())

    # Simular scan sin crawl ni fingerprint ni subdominios
    with patch("core.engine.TechFingerprinter") as mock_fp, \
         patch("core.engine.WebCrawler"):
        mock_fp.return_value.analyze.return_value = {
            'server': [], 'powered_by': [], 'cms_framework': [], 'confidence': 'LOW'
        }

        results1 = engine.scan("http://test.com", crawl=False)
        count1 = len(results1)

        results2 = engine.scan("http://test.com", crawl=False)
        count2 = len(results2)

        # Ambos scans deben tener la misma cantidad (no acumulada)
        assert count1 == count2


def test_scan_sin_crawl_usa_url_directa():
    """Con crawl=False, el engine debe atacar solo la URL proporcionada."""
    engine = VulnSeekerEngine(enable_subdomains=False)
    urls_atacadas = []

    class SpyModule(ScannerModule):
        @property
        def name(self) -> str:
            return "Spy"

        @property
        def description(self) -> str:
            return "Espía"

        def run(self, target: Target) -> list[Vulnerability]:
            urls_atacadas.append(target.url)
            return []

    engine.register_module(SpyModule())

    with patch("core.engine.TechFingerprinter") as mock_fp:
        mock_fp.return_value.analyze.return_value = {
            'server': [], 'powered_by': [], 'cms_framework': [], 'confidence': 'LOW'
        }
        engine.scan("http://example.com", crawl=False)

    assert "http://example.com" in urls_atacadas
