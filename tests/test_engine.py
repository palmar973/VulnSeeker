"""
Tests unitarios: Motor VulnSeeker (engine.py).
Valida registro de módulos, reset de resultados y flujo de escaneo.
"""
import pytest
from unittest.mock import patch, MagicMock
from core.engine import VulnSeekerEngine
from core.models import ScannerModule, Target, Vulnerability, Severity, PageElement


@pytest.fixture(autouse=True)
def _neutralizar_autologin():
    """Evita I/O de red real: el auto-login DVWA se prueba aparte (test_autologin.py).

    Sin esto, cada scan() dispararía requests.get() contra el host de prueba,
    volviendo la suite no determinista y dependiente de la red.
    """
    with patch.object(VulnSeekerEngine, "_check_and_perform_autologin",
                      lambda self, url: None):
        yield


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


def test_deduplicacion_elimina_duplicados():
    """El engine debe eliminar hallazgos duplicados (mismo name + url + payload)."""
    engine = VulnSeekerEngine(enable_subdomains=False)

    class DuplicatorModule(ScannerModule):
        @property
        def name(self) -> str:
            return "Duplicator"

        @property
        def description(self) -> str:
            return "Genera duplicados"

        def run(self, target: Target) -> list[Vulnerability]:
            # Retorna 3 vulns: 2 idénticas + 1 distinta
            return [
                Vulnerability(name="XSS", severity=Severity.HIGH,
                              description="XSS en param", target_url=target.url,
                              payload="<script>alert(1)</script>"),
                Vulnerability(name="XSS", severity=Severity.HIGH,
                              description="XSS en param", target_url=target.url,
                              payload="<script>alert(1)</script>"),
                Vulnerability(name="SQLi", severity=Severity.CRITICAL,
                              description="SQLi en param", target_url=target.url,
                              payload="' OR 1=1--"),
            ]

    engine.register_module(DuplicatorModule())

    with patch("core.engine.TechFingerprinter") as mock_fp:
        mock_fp.return_value.analyze.return_value = {
            'server': [], 'powered_by': [], 'cms_framework': [], 'confidence': 'LOW'
        }
        results = engine.scan("http://example.com", crawl=False)

    # Debe haber 2 resultados únicos, no 3
    assert len(results) == 2
    names = {v.name for v in results}
    assert names == {"XSS", "SQLi"}
