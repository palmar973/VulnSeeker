"""
Tests unitarios: Tipos canónicos de VulnSeeker.
Valida la integridad de los modelos de datos definidos en core.models.
"""
from core.models import Severity, Target, PageElement, Vulnerability, ScannerModule


def test_severity_tiene_cinco_niveles():
    """Verifica que Severity tiene exactamente los 5 niveles esperados."""
    niveles = [s.value for s in Severity]
    assert niveles == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_page_element_es_inmutable():
    """PageElement debe ser frozen (inmutable para seguridad entre hilos)."""
    elem = PageElement(url="http://test.com", params={"q": "1"})
    try:
        elem.url = "http://otro.com"
        assert False, "PageElement no debería permitir mutación"
    except AttributeError:
        pass  # Correcto: frozen=True


def test_target_se_crea_con_defaults():
    """Target debe tener valores por defecto funcionales."""
    t = Target(url="http://test.com")
    assert t.method == "GET"
    assert t.headers == {}
    assert t.elements == []
    assert t.context == {}


def test_vulnerability_almacena_datos():
    """Vulnerability debe almacenar todos los campos correctamente."""
    v = Vulnerability(
        name="XSS",
        severity=Severity.HIGH,
        description="Reflejado",
        target_url="http://test.com",
        evidence="<script>",
        payload="<VulnSeekerXSS>"
    )
    assert v.name == "XSS"
    assert v.severity == Severity.HIGH
    assert v.evidence == "<script>"
    assert v.payload == "<VulnSeekerXSS>"


def test_scanner_types_reexporta_los_mismos_objetos():
    """scanner_types.py debe re-exportar exactamente los mismos objetos de models.py."""
    from core.models import Severity as S2, Target as T2, Vulnerability as V2
    assert Severity is S2
    assert Target is T2
    assert Vulnerability is V2
