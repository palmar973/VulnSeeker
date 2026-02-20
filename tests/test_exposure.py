import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.exposure_scanner import ExposureScanner


@pytest.fixture
def scanner():
    return ExposureScanner()


@patch("modules.exposure_scanner.requests.get")
def test_detecta_env_expuesto(mock_get, scanner):
    """.env accesible y devuelve contenido no-HTML → alerta HIGH."""
    resp = MagicMock(status_code=200, text="DB_PASSWORD=secret123\nAPI_KEY=abc")
    mock_get.return_value = resp
    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    env_vulns = [v for v in vulns if ".env" in v.name]
    assert len(env_vulns) >= 1
    assert env_vulns[0].severity.name == "HIGH"


@patch("modules.exposure_scanner.requests.get")
def test_ignora_404(mock_get, scanner):
    """Archivos que devuelven 404 → sin alertas."""
    resp = MagicMock(status_code=404, text="Not Found")
    mock_get.return_value = resp
    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.exposure_scanner.requests.get")
def test_ignora_respuesta_html(mock_get, scanner):
    """200 pero con HTML genérico (soft 404) → sin alertas."""
    resp = MagicMock(status_code=200, text="<!DOCTYPE html><html><body>404</body></html>")
    mock_get.return_value = resp
    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    assert len(vulns) == 0
