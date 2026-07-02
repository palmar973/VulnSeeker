"""
Tests unitarios: LFI Scanner (modules/lfi_scanner.py).

Cubre la detección por contenido reflejado (/etc/passwd, win.ini), la detección
error-based por fugas de excepciones de E/S y la guarda de baseline anti falso
positivo. El envío HTTP vive en modules/injection_points.py, así que los mocks se
aplican sobre modules.injection_points.requests.
"""
import pytest
from unittest.mock import patch, MagicMock

from core.models import Target, PageElement
from modules.lfi_scanner import LFIScanner


@pytest.fixture
def scanner():
    return LFIScanner()


def _baseline_luego(payload_resp):
    """side_effect: 1ª llamada (baseline benigno) limpia; el resto, payload_resp."""
    limpia = MagicMock(text="<html>home</html>")
    llamadas = {"n": 0}

    def side_effect(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else payload_resp

    return side_effect


@patch("modules.injection_points.requests.get")
def test_detecta_lfi_etc_passwd(mock_get, scanner):
    """root:x:0:0 ausente del baseline → LFI detectado (CRITICAL)."""
    passwd = MagicMock(text="root:x:0:0:root:/root:/bin/bash")
    mock_get.side_effect = _baseline_luego(passwd)

    vulns = scanner.run(Target(url="http://localhost/vuln?page=home"))
    lfi = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi) >= 1
    assert lfi[0].severity.name == "CRITICAL"


@patch("modules.injection_points.requests.get")
def test_detecta_lfi_win_ini(mock_get, scanner):
    """[extensions]/[fonts] ausentes del baseline → LFI en Windows detectado."""
    win_ini = MagicMock(text="[fonts]\n[extensions]")
    mock_get.side_effect = _baseline_luego(win_ini)

    vulns = scanner.run(Target(url="http://localhost/vuln?file=test"))
    lfi = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi) >= 1


@patch("modules.injection_points.requests.get")
def test_detecta_lfi_error_based(mock_get, scanner):
    """Sin reflejar el archivo, una fuga de FileNotFoundException delata el traversal."""
    err = MagicMock(text="500: java.io.FileNotFoundException: ../../../etc/passwd (No such file)")
    mock_get.side_effect = _baseline_luego(err)

    vulns = scanner.run(Target(url="http://localhost/vuln?file=test"))
    lfi = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi) >= 1
    assert "error de E/S" in lfi[0].description


@patch("modules.injection_points.requests.get")
def test_no_reporta_lfi_si_evidencia_ya_en_baseline(mock_get, scanner):
    """Si 'root:x:0:0' ya estaba en el baseline, no es LFI (FP preexistente)."""
    resp = MagicMock(text="root:x:0:0 ya aparecía en la página")
    mock_get.return_value = resp  # baseline == ataque
    vulns = scanner.run(Target(url="http://localhost/vuln?page=home"))
    lfi = [v for v in vulns if v.name == "Local File Inclusion (LFI)"]
    assert len(lfi) == 0


@patch("modules.injection_points.requests.get")
def test_no_reporta_error_si_ya_en_baseline(mock_get, scanner):
    """Si la excepción de E/S ya estaba en el baseline, no se atribuye al payload."""
    resp = MagicMock(text="java.io.FileNotFoundException en el pie de página")
    mock_get.return_value = resp
    vulns = scanner.run(Target(url="http://localhost/vuln?file=test"))
    assert len([v for v in vulns if v.name == "Local File Inclusion (LFI)"]) == 0


@patch("modules.injection_points.requests.get")
def test_no_reporta_respuesta_limpia(mock_get, scanner):
    """Respuesta HTML normal → sin LFI."""
    mock_get.return_value = MagicMock(text="<html>Welcome</html>")
    vulns = scanner.run(Target(url="http://localhost/vuln?page=home"))
    assert len(vulns) == 0


@patch("modules.injection_points.requests.post")
def test_detecta_lfi_en_form_post(mock_post, scanner):
    """Nuevo vector: LFI también se prueba en formularios POST."""
    limpia = MagicMock(text="<html>home</html>")
    passwd = MagicMock(text="root:x:0:0:root:/root:/bin/bash")
    llamadas = {"n": 0}

    def side_effect(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else passwd

    mock_post.side_effect = side_effect
    element = PageElement(url="http://localhost/load", method="POST",
                          params={"file": "home"}, is_form=True)
    vulns = scanner.run(Target(url="http://localhost/load", elements=[element]))
    assert len([v for v in vulns if v.name == "Local File Inclusion (LFI)"]) >= 1
