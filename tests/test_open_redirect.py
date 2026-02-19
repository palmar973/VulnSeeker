"""Tests para el módulo Open Redirect Scanner."""

from unittest.mock import MagicMock, patch
from modules.open_redirect import OpenRedirectScanner
from core.models import Target, PageElement, Severity


def test_detecta_redirect_con_location_externa():
    """Debe reportar vuln cuando el servidor redirige al dominio inyectado."""
    scanner = OpenRedirectScanner()
    target = Target(
        url="http://test.com/login?redirect=http://test.com/home",
        elements=[PageElement(url="http://test.com/login", params={"redirect": "http://test.com/home"})]
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "http://evil.com"}

    with patch("modules.open_redirect.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert vulns[0].name == "Open Redirect"
    assert vulns[0].severity == Severity.MEDIUM


def test_no_reporta_si_location_es_interna():
    """No debe reportar si el Location apunta al mismo sitio."""
    scanner = OpenRedirectScanner()
    target = Target(
        url="http://test.com/login?redirect=/dashboard",
        elements=[PageElement(url="http://test.com/login", params={"redirect": "/dashboard"})]
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "http://test.com/dashboard"}

    with patch("modules.open_redirect.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_ignora_params_no_relacionados_con_redirect():
    """Si no hay parámetros de redirección, no debe probar nada."""
    scanner = OpenRedirectScanner()
    target = Target(
        url="http://test.com/search?q=hello&page=1",
        elements=[PageElement(url="http://test.com/search", params={"q": "hello", "page": "1"})]
    )

    vulns = scanner.run(target)
    assert len(vulns) == 0


def test_funciona_sin_elements_ni_params():
    """No debe fallar si no hay elementos ni parámetros en la URL."""
    scanner = OpenRedirectScanner()
    target = Target(url="http://test.com/about")

    vulns = scanner.run(target)
    assert len(vulns) == 0
