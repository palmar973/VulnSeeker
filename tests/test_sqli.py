"""
Tests unitarios: SQLi Module (modules/sqli_module.py).
Valida la detección de errores SQL en respuestas HTTP simuladas.
"""
from unittest.mock import patch, MagicMock
from modules.sqli_module import SQLInjectionScanner
from core.models import Target, PageElement, Severity


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


def test_detecta_sqli_en_form_post():
    """Debe detectar SQLi en formularios POST con campos inyectables."""
    scanner = SQLInjectionScanner()
    element = PageElement(
        url="http://test.com/login.php",
        method="POST",
        params={"username": "admin", "password": "test"},
        is_form=True
    )
    target = Target(url="http://test.com/login.php", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "You have an error in your SQL syntax"

    with patch("modules.sqli_module.requests.post", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert "POST" in vulns[0].name
    assert vulns[0].severity == Severity.HIGH


def test_replace_strategy_detecta_sqli():
    """La estrategia de reemplazo completo debe detectar SQLi también."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/page?id=5")

    call_count = 0

    def mock_get_side_effect(url, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        # La concatenación (id=5') no dispara error, pero el reemplazo (id=') sí
        if "id=%27" in url or "id='" in url:
            resp.text = "Warning: mysql_fetch_array()"
        else:
            resp.text = "<html>OK</html>"
        return resp

    with patch("modules.sqli_module.requests.get", side_effect=mock_get_side_effect):
        vulns = scanner.run(target)

    assert len(vulns) >= 1

