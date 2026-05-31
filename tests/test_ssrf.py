import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.ssrf_scanner import SSRFScanner


@pytest.fixture
def scanner():
    return SSRFScanner()


@patch("modules.ssrf_scanner.requests.Session")
def test_detecta_ssrf_con_contenido_interno(MockSession, scanner):
    """Respuesta incluye contenido de localhost → SSRF HIGH."""
    session = MockSession.return_value
    resp = MagicMock()
    resp.text = "<html><body>It works on localhost</body></html>"
    resp.status_code = 200
    session.get.return_value = resp

    target = Target(url="http://example.com/fetch?url=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) >= 1
    assert ssrf_vulns[0].severity.name == "HIGH"


@patch("modules.ssrf_scanner.requests.Session")
def test_detecta_ssrf_con_metadata_aws(MockSession, scanner):
    """Respuesta incluye metadata AWS (ami-id) → SSRF HIGH."""
    session = MockSession.return_value
    resp = MagicMock()
    resp.text = "ami-id\ninstance-id\nhostname"
    resp.status_code = 200
    session.get.return_value = resp

    target = Target(url="http://example.com/proxy?url=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) >= 1


@patch("modules.ssrf_scanner.requests.Session")
def test_no_reporta_respuesta_normal(MockSession, scanner):
    """Respuesta sin contenido interno → sin SSRF."""
    session = MockSession.return_value
    resp = MagicMock()
    resp.text = "<html><body>Normal page content</body></html>"
    resp.status_code = 200
    session.get.return_value = resp

    target = Target(url="http://example.com/fetch?url=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) == 0


@patch("modules.ssrf_scanner.requests.Session")
def test_sin_parametros_sospechosos(MockSession, scanner):
    """URL sin parámetros de tipo URL → sin escaneo, sin vulns."""
    session = MockSession.return_value

    target = Target(url="http://example.com/page?search=test&lang=en")
    vulns = scanner.run(target)
    assert len(vulns) == 0
    # No se deben hacer peticiones si no hay parámetros sospechosos
    session.get.assert_not_called()


@patch("modules.ssrf_scanner.requests.Session")
def test_detecta_ssrf_por_cambio_tamano(MockSession, scanner):
    """Respuesta con tamaño significativamente distinto al baseline → SSRF HIGH."""
    session = MockSession.return_value

    baseline_resp = MagicMock()
    baseline_resp.text = "short"
    baseline_resp.status_code = 200

    ssrf_resp = MagicMock()
    ssrf_resp.text = "x" * 500  # Mucho más grande que el baseline
    ssrf_resp.status_code = 200

    session.get.side_effect = [baseline_resp, ssrf_resp]

    target = Target(url="http://example.com/load?src=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) >= 1
