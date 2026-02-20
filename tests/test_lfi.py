import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.lfi_scanner import LFIScanner


@pytest.fixture
def scanner():
    return LFIScanner()


@patch("modules.lfi_scanner.requests.get")
def test_detecta_lfi_etc_passwd(mock_get, scanner):
    """Respuesta con root:x:0:0 → LFI detectado (CRITICAL)."""
    mock_get.return_value = MagicMock(text="root:x:0:0:root:/root:/bin/bash")
    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    lfi_vulns = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi_vulns) >= 1
    assert lfi_vulns[0].severity.name == "CRITICAL"


@patch("modules.lfi_scanner.requests.get")
def test_detecta_lfi_win_ini(mock_get, scanner):
    """Respuesta con [extensions] o [fonts] → LFI en Windows detectado."""
    mock_get.return_value = MagicMock(text="[fonts]\n[extensions]")
    target = Target(url="http://localhost/vuln?file=test")
    vulns = scanner.run(target)
    lfi_vulns = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi_vulns) >= 1


@patch("modules.lfi_scanner.requests.get")
def test_no_reporta_respuesta_limpia(mock_get, scanner):
    """Respuesta HTML normal → sin LFI."""
    mock_get.return_value = MagicMock(text="<html>Welcome</html>")
    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    assert len(vulns) == 0
