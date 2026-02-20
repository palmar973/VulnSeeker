import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.sensitive_data_scanner import SensitiveDataExposure


@pytest.fixture
def scanner():
    return SensitiveDataExposure()


def _mock_response(html, content_type="text/html"):
    resp = MagicMock()
    resp.text = html
    resp.headers = {"Content-Type": content_type}
    return resp


@patch("modules.sensitive_data_scanner.requests.get")
def test_detecta_api_key(mock_get, scanner):
    """API key en HTML → API Key Exposed (CRITICAL)."""
    html = '<script>var config = {api_key: "sk_live_abcdef1234567890abcdef"};</script>'
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/app")
    vulns = scanner.run(target)
    api_vulns = [v for v in vulns if v.name == "API Key Exposed"]
    assert len(api_vulns) == 1
    assert api_vulns[0].severity.name == "CRITICAL"


@patch("modules.sensitive_data_scanner.requests.get")
def test_detecta_password_hardcoded(mock_get, scanner):
    """Password en código → Hardcoded Password (HIGH)."""
    html = '<script>var db = {password: "supersecret123"};</script>'
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/app")
    vulns = scanner.run(target)
    pwd_vulns = [v for v in vulns if v.name == "Hardcoded Password"]
    assert len(pwd_vulns) == 1
    assert pwd_vulns[0].severity.name == "HIGH"


@patch("modules.sensitive_data_scanner.requests.get")
def test_detecta_aws_key(mock_get, scanner):
    """AWS Access Key en HTML → CRITICAL."""
    html = '<div>AKIAIOSFODNN7EXAMPLE</div>'
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/debug")
    vulns = scanner.run(target)
    aws_vulns = [v for v in vulns if v.name == "AWS Access Key"]
    assert len(aws_vulns) == 1


@patch("modules.sensitive_data_scanner.requests.get")
def test_detecta_comentario_sensible(mock_get, scanner):
    """Comentario HTML con TODO/password → Sensitive HTML Comment."""
    html = '<html><!-- TODO: remove admin password from config --></html>'
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/page")
    vulns = scanner.run(target)
    comment_vulns = [v for v in vulns if v.name == "Sensitive HTML Comment"]
    assert len(comment_vulns) == 1


@patch("modules.sensitive_data_scanner.requests.get")
def test_no_reporta_pagina_limpia(mock_get, scanner):
    """HTML sin datos sensibles → sin alertas."""
    html = '<html><body><h1>Bienvenido a mi sitio web</h1></body></html>'
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.sensitive_data_scanner.requests.get")
def test_ignora_contenido_no_html(mock_get, scanner):
    """Respuestas no-HTML se ignoran."""
    mock_get.return_value = _mock_response('{"api_key": "secret"}', "application/json")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    assert len(vulns) == 0
