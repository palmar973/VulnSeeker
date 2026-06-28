import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.rfi_scanner import RFIScanner


@pytest.fixture
def scanner():
    return RFIScanner()


@patch("modules.rfi_scanner.requests.Session")
def test_detecta_rfi_con_keyword(MockSession, scanner):
    """Contenido remoto (User-agent:) ausente del baseline → RFI CRITICAL."""
    session = MockSession.return_value
    limpia = MagicMock(text="<html>home</html>")
    remota = MagicMock(text="User-agent: *\nDisallow: /admin")

    llamadas = {"n": 0}

    def get_side_effect(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else remota  # 1ª llamada = baseline limpio

    session.get.side_effect = get_side_effect

    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    rfi_vulns = [v for v in vulns if v.name == "Remote File Inclusion (RFI)"]
    assert len(rfi_vulns) >= 1
    assert rfi_vulns[0].severity.name == "CRITICAL"


@patch("modules.rfi_scanner.requests.Session")
def test_no_reporta_rfi_si_keyword_ya_en_baseline(MockSession, scanner):
    """Si 'User-agent:' ya estaba en el baseline (p.ej. robots.txt propio), no es RFI."""
    session = MockSession.return_value
    resp = MagicMock(text="User-agent: *\nDisallow: /admin")  # presente siempre
    session.get.return_value = resp

    target = Target(url="http://localhost/vuln?page=home")
    vulns = scanner.run(target)
    rfi_vulns = [v for v in vulns if v.name == "Remote File Inclusion (RFI)"]
    assert len(rfi_vulns) == 0


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


@patch("modules.rfi_scanner.requests.Session")
def test_no_confunde_open_redirect_con_rfi(MockSession, scanner):
    """Un Open Redirect (302 hacia la URL del payload) no debe reportarse como RFI.

    Regresión: antes el módulo seguía la redirección hasta el recurso remoto y
    confundía su contenido (p. ej. robots.txt) con una inclusión remota real.
    """
    session = MockSession.return_value
    limpia = MagicMock(text="<html>home</html>", status_code=200)
    # Con allow_redirects=False, el open redirect devuelve 302 sin el contenido remoto.
    redir = MagicMock(text="", status_code=302,
                      headers={"Location": "http://www.google.com/robots.txt"})

    llamadas = {"n": 0}

    def get_side_effect(url, **kwargs):
        # El módulo debe solicitar explícitamente NO seguir redirecciones.
        assert kwargs.get("allow_redirects") is False, "RFI debe usar allow_redirects=False"
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else redir

    session.get.side_effect = get_side_effect

    target = Target(url="http://localhost/open_redirect?redirect=info.php")
    vulns = scanner.run(target)
    rfi_vulns = [v for v in vulns if v.name == "Remote File Inclusion (RFI)"]
    assert len(rfi_vulns) == 0
