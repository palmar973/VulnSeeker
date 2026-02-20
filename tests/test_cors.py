import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.cors_scanner import CORSMisconfigScanner


@pytest.fixture
def scanner():
    return CORSMisconfigScanner()


def _mock_response(acao="", acac=""):
    resp = MagicMock()
    headers = {}
    if acao:
        headers["Access-Control-Allow-Origin"] = acao
    if acac:
        headers["Access-Control-Allow-Credentials"] = acac
    resp.headers = headers
    return resp


@patch("modules.cors_scanner.requests.get")
def test_detecta_cors_wildcard(mock_get, scanner):
    """ACAO: * → CORS Wildcard Origin (MEDIUM)."""
    mock_get.return_value = _mock_response(acao="*")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    wildcard_vulns = [v for v in vulns if v.name == "CORS Wildcard Origin"]
    assert len(wildcard_vulns) == 1
    assert wildcard_vulns[0].severity.name == "MEDIUM"


@patch("modules.cors_scanner.requests.get")
def test_detecta_wildcard_con_credentials(mock_get, scanner):
    """ACAO: * + ACAC: true → CRITICAL."""
    mock_get.return_value = _mock_response(acao="*", acac="true")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    crit_vulns = [v for v in vulns if v.name == "CORS Wildcard With Credentials"]
    assert len(crit_vulns) == 1
    assert crit_vulns[0].severity.name == "CRITICAL"


@patch("modules.cors_scanner.requests.get")
def test_detecta_origin_reflection(mock_get, scanner):
    """Servidor refleja origin malicioso → CORS Origin Reflection (HIGH)."""
    mock_get.return_value = _mock_response(acao="https://evil-attacker.com")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    reflect_vulns = [v for v in vulns if v.name == "CORS Origin Reflection"]
    assert len(reflect_vulns) == 1
    assert reflect_vulns[0].severity.name == "HIGH"


@patch("modules.cors_scanner.requests.get")
def test_origin_reflection_con_credentials_es_critical(mock_get, scanner):
    """Refleja origin + credentials → CRITICAL."""
    mock_get.return_value = _mock_response(
        acao="https://evil-attacker.com", acac="true"
    )
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    reflect_vulns = [v for v in vulns if v.name == "CORS Origin Reflection"]
    assert len(reflect_vulns) == 1
    assert reflect_vulns[0].severity.name == "CRITICAL"


@patch("modules.cors_scanner.requests.get")
def test_no_reporta_sin_cors_headers(mock_get, scanner):
    """Sin ACAO header → no aplica, sin alertas."""
    mock_get.return_value = _mock_response()
    target = Target(url="http://localhost/page")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.cors_scanner.requests.get")
def test_cors_seguro_no_reporta(mock_get, scanner):
    """ACAO con dominio legítimo → sin alertas."""
    mock_get.return_value = _mock_response(acao="https://trusted-site.com")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    assert len(vulns) == 0
