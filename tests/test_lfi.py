import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.lfi_scanner import LFIScanner


@pytest.fixture
def scanner():
    return LFIScanner()


@patch("modules.lfi_scanner.requests.get")
def test_detecta_lfi_etc_passwd(mock_get, scanner):
    """root:x:0:0 ausente del baseline → LFI detectado (CRITICAL)."""
    limpia = MagicMock(text="<html>home</html>")
    passwd = MagicMock(text="root:x:0:0:root:/root:/bin/bash")

    llamadas = {"n": 0}

    def get_side_effect(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else passwd  # 1ª llamada = baseline limpio

    mock_get.side_effect = get_side_effect
    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    lfi_vulns = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi_vulns) >= 1
    assert lfi_vulns[0].severity.name == "CRITICAL"


@patch("modules.lfi_scanner.requests.get")
def test_detecta_lfi_win_ini(mock_get, scanner):
    """[extensions]/[fonts] ausentes del baseline → LFI en Windows detectado."""
    limpia = MagicMock(text="<html>home</html>")
    win_ini = MagicMock(text="[fonts]\n[extensions]")

    llamadas = {"n": 0}

    def get_side_effect(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else win_ini

    mock_get.side_effect = get_side_effect
    target = Target(url="http://localhost/vuln?file=test")
    vulns = scanner.run(target)
    lfi_vulns = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi_vulns) >= 1


@patch("modules.lfi_scanner.requests.get")
def test_no_reporta_lfi_si_evidencia_ya_en_baseline(mock_get, scanner):
    """Si 'root:x:0:0' ya estaba en el baseline, no es LFI (FP pre-existente)."""
    resp = MagicMock(text="root:x:0:0 ya aparecía en la página")
    mock_get.return_value = resp  # baseline == ataque
    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    lfi_vulns = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi_vulns) == 0


@patch("modules.lfi_scanner.requests.get")
def test_no_reporta_respuesta_limpia(mock_get, scanner):
    """Respuesta HTML normal → sin LFI."""
    mock_get.return_value = MagicMock(text="<html>Welcome</html>")
    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    assert len(vulns) == 0
