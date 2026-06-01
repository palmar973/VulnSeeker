import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.email_harvester import EmailHarvester


@pytest.fixture
def scanner():
    return EmailHarvester()


@patch("modules.email_harvester.requests.get")
def test_detecta_emails_en_pagina(mock_get, scanner):
    """Página con emails visibles → Email Disclosure INFO."""
    resp = MagicMock()
    resp.ok = True
    resp.text = '<html>Contact us at admin@example.com or support@example.com</html>'
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    email_vulns = [v for v in vulns if v.name == "Email Disclosure"]
    assert len(email_vulns) == 1
    assert email_vulns[0].severity.name == "INFO"
    assert "admin@example.com" in email_vulns[0].description
    assert "support@example.com" in email_vulns[0].description


@patch("modules.email_harvester.requests.get")
def test_sin_emails_no_reporta(mock_get, scanner):
    """Página sin emails → sin hallazgos."""
    resp = MagicMock()
    resp.ok = True
    resp.text = '<html><body>No contact info here</body></html>'
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    email_vulns = [v for v in vulns if v.name == "Email Disclosure"]
    assert len(email_vulns) == 0


@patch("modules.email_harvester.requests.get")
def test_emails_deduplicados(mock_get, scanner):
    """Mismo email en múltiples páginas → solo un hallazgo con emails únicos."""
    resp = MagicMock()
    resp.ok = True
    resp.text = '<html>info@test.com and again info@test.com</html>'
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    email_vulns = [v for v in vulns if v.name == "Email Disclosure"]
    assert len(email_vulns) == 1
    # Solo debe aparecer una vez en la descripción
    assert email_vulns[0].description.count("info@test.com") == 1


@patch("modules.email_harvester.requests.get")
def test_maneja_error_de_conexion(mock_get, scanner):
    """Error de conexión en todas las páginas → sin hallazgos ni crash."""
    resp = MagicMock()
    resp.ok = False
    resp.text = ""
    mock_get.return_value = resp

    target = Target(url="http://example.com")
    vulns = scanner.run(target)
    assert len(vulns) == 0
