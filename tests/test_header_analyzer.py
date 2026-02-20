import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.header_analyzer import HeaderAnalyzer


@pytest.fixture
def analyzer():
    return HeaderAnalyzer()


@patch("modules.header_analyzer.requests.head")
def test_detecta_headers_faltantes(mock_head, analyzer):
    """Sin ningún header de seguridad → 4 vulnerabilidades."""
    resp = MagicMock()
    resp.headers = {}
    mock_head.return_value = resp
    target = Target(url="http://localhost/")
    vulns = analyzer.run(target)
    names = [v.name for v in vulns]
    assert "Missing X-Frame-Options" in names
    assert "Missing Content-Security-Policy" in names
    assert "Missing HSTS" in names
    assert "Missing X-Content-Type-Options" in names


@patch("modules.header_analyzer.requests.head")
def test_no_reporta_con_todos_los_headers(mock_head, analyzer):
    """Todos los headers presentes → sin vulnerabilidades."""
    resp = MagicMock()
    resp.headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }
    mock_head.return_value = resp
    target = Target(url="http://localhost/")
    vulns = analyzer.run(target)
    assert len(vulns) == 0


@patch("modules.header_analyzer.requests.head")
def test_detecta_csp_faltante_solo(mock_head, analyzer):
    """Solo falta CSP → 1 vulnerabilidad MEDIUM."""
    resp = MagicMock()
    resp.headers = {
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }
    mock_head.return_value = resp
    target = Target(url="http://localhost/")
    vulns = analyzer.run(target)
    assert len(vulns) == 1
    assert vulns[0].name == "Missing Content-Security-Policy"
    assert vulns[0].severity.name == "MEDIUM"
