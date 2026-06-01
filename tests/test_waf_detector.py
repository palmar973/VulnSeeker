import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.waf_detector import WAFDetector


@pytest.fixture
def scanner():
    return WAFDetector()


@patch("modules.waf_detector.requests.get")
def test_detecta_cloudflare_por_header(mock_get, scanner):
    """Header 'server: cloudflare' → WAF Detected INFO."""
    resp = MagicMock()
    resp.headers = {"Server": "cloudflare", "CF-RAY": "abc123"}
    resp.cookies.get_dict.return_value = {}
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    waf_vulns = [v for v in vulns if v.name == "WAF Detected"]
    assert len(waf_vulns) == 1
    assert waf_vulns[0].severity.name == "INFO"
    assert "Cloudflare" in waf_vulns[0].description


@patch("modules.waf_detector.requests.get")
def test_detecta_aws_waf_por_cookie(mock_get, scanner):
    """Cookie 'aws-waf-token' present → WAF Detected INFO."""
    resp = MagicMock()
    resp.headers = {"Content-Type": "text/html"}
    resp.cookies.get_dict.return_value = {"aws-waf-token": "xyz"}
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    waf_vulns = [v for v in vulns if v.name == "WAF Detected"]
    assert len(waf_vulns) == 1
    assert "AWS WAF" in waf_vulns[0].description


@patch("modules.waf_detector.requests.get")
def test_no_detecta_waf_respuesta_limpia(mock_get, scanner):
    """Sin headers ni cookies de WAF → sin hallazgos."""
    resp = MagicMock()
    resp.headers = {"Content-Type": "text/html", "Server": "nginx"}
    resp.cookies.get_dict.return_value = {}
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.waf_detector.requests.get")
def test_maneja_error_de_conexion(mock_get, scanner):
    """Error de conexión → retorna lista vacía sin crash."""
    mock_get.side_effect = ConnectionError("Connection refused")

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    assert len(vulns) == 0
