"""
Tests unitarios: SQLi Module (modules/sqli_module.py).
Valida la detección de errores SQL en respuestas HTTP simuladas.
"""
from unittest.mock import patch, MagicMock
from modules.sqli_module import SQLInjectionScanner
from core.models import Target, Severity


def test_detecta_error_mysql_en_respuesta():
    """Debe reportar SQLi cuando la respuesta contiene un error MySQL."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/page?id=1")

    mock_resp = MagicMock()
    mock_resp.text = "You have an error in your SQL syntax near '1'' at line 1"

    with patch("modules.sqli_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH
    assert "SQL" in vulns[0].name


def test_no_reporta_sqli_en_respuesta_limpia():
    """No debe reportar SQLi si la respuesta no contiene errores de BD."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/page?id=1")

    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Página normal sin errores</body></html>"

    with patch("modules.sqli_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_ignora_urls_sin_parametros():
    """URLs sin query params no deben ser analizadas para SQLi."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/index.html")

    vulns = scanner.run(target)
    assert len(vulns) == 0
