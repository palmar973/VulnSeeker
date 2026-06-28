import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.ssrf_scanner import SSRFScanner


@pytest.fixture
def scanner():
    return SSRFScanner()


@patch("modules.ssrf_scanner.requests.Session")
def test_detecta_ssrf_con_contenido_interno(MockSession, scanner):
    """Contenido de localhost ausente del baseline → SSRF HIGH."""
    session = MockSession.return_value
    limpia = MagicMock(text="<html>safe</html>", status_code=200)
    interno = MagicMock(text="<html><body>It works on localhost</body></html>", status_code=200)

    llamadas = {"n": 0}

    def get_side_effect(*args, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else interno  # 1ª llamada = baseline limpio

    session.get.side_effect = get_side_effect

    target = Target(url="http://example.com/fetch?url=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) >= 1
    assert ssrf_vulns[0].severity.name == "HIGH"


@patch("modules.ssrf_scanner.requests.Session")
def test_detecta_ssrf_con_metadata_aws(MockSession, scanner):
    """Metadata AWS (ami-id) ausente del baseline → SSRF HIGH."""
    session = MockSession.return_value
    limpia = MagicMock(text="<html>safe</html>", status_code=200)
    interno = MagicMock(text="ami-id\ninstance-id\nhostname", status_code=200)

    llamadas = {"n": 0}

    def get_side_effect(*args, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else interno

    session.get.side_effect = get_side_effect

    target = Target(url="http://example.com/proxy?url=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) >= 1


@patch("modules.ssrf_scanner.requests.Session")
def test_no_reporta_ssrf_si_keyword_ya_en_baseline(MockSession, scanner):
    """Si 'localhost' ya aparece en el baseline (y el tamaño no cambia), no es SSRF."""
    session = MockSession.return_value
    resp = MagicMock(text="<html>localhost dashboard</html>", status_code=200)
    session.get.return_value = resp  # baseline == ataque (mismo texto y tamaño)

    target = Target(url="http://example.com/fetch?url=http://safe.com")
    vulns = scanner.run(target)
    ssrf_vulns = [v for v in vulns if v.name == "Server-Side Request Forgery (SSRF)"]
    assert len(ssrf_vulns) == 0


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
