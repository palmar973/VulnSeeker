import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.rfi_scanner import RFIScanner


@pytest.fixture
def scanner():
    return RFIScanner()


@patch("modules.rfi_scanner.requests.Session")
def test_detecta_rfi_con_keyword(MockSession, scanner):
    """Respuesta incluye contenido remoto (User-agent:) → RFI CRITICAL."""
    session = MockSession.return_value
    resp = MagicMock()
    resp.text = "User-agent: *\nDisallow: /admin"
    session.get.return_value = resp

    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    rfi_vulns = [v for v in vulns if v.name == "Remote File Inclusion (RFI)"]
    assert len(rfi_vulns) >= 1
    assert rfi_vulns[0].severity.name == "CRITICAL"


@patch("modules.rfi_scanner.requests.Session")
def test_no_reporta_respuesta_normal(MockSession, scanner):
    """Respuesta sin contenido remoto → sin RFI."""
    session = MockSession.return_value
    resp = MagicMock()
    resp.text = "<html><body>Normal page</body></html>"
    session.get.return_value = resp

    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    rfi_vulns = [v for v in vulns if v.name == "Remote File Inclusion (RFI)"]
    assert len(rfi_vulns) == 0
