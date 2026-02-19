"""
Tests unitarios: XSS Module (modules/xss_module.py).
Valida la detección de XSS reflejado mediante canario.
"""
from unittest.mock import patch, MagicMock
from modules.xss_module import XSSScanner
from core.models import Target, Severity


def test_detecta_xss_reflejado():
    """Debe reportar XSS cuando el canario aparece en la respuesta."""
    scanner = XSSScanner()
    target = Target(url="http://test.com/search?q=hola")

    mock_resp = MagicMock()
    # Simular que el servidor refleja el payload sin sanitizar
    mock_resp.text = "<html><body>Resultados: <VulnSeekerXSS></body></html>"

    with patch("modules.xss_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.MEDIUM
    assert "XSS" in vulns[0].name


def test_no_reporta_xss_si_canario_es_sanitizado():
    """No debe reportar XSS si el canario no aparece en la respuesta."""
    scanner = XSSScanner()
    target = Target(url="http://test.com/search?q=hola")

    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Resultados: &lt;VulnSeekerXSS&gt;</body></html>"

    with patch("modules.xss_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_ignora_urls_sin_parametros():
    """URLs sin query params no deben ser analizadas para XSS."""
    scanner = XSSScanner()
    target = Target(url="http://test.com/index.html")

    vulns = scanner.run(target)
    assert len(vulns) == 0
