import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.cookie_scanner import CookieScanner


@pytest.fixture
def scanner():
    return CookieScanner()


def _make_cookie(name, secure=False, httponly=False):
    """Helper para crear un mock de cookie con las banderas deseadas."""
    cookie = MagicMock()
    cookie.name = name
    cookie.secure = secure
    cookie.has_nonstandard_attr = MagicMock(return_value=httponly)
    cookie._rest = {"HttpOnly": ""} if httponly else {}
    return cookie


@patch("modules.cookie_scanner.requests.Session")
def test_detecta_cookie_sin_httponly(MockSession, scanner):
    """Cookie sin HttpOnly → vulnerabilidad HIGH."""
    session = MockSession.return_value
    resp = MagicMock()

    insecure_cookie = _make_cookie("PHPSESSID", secure=True, httponly=False)
    session.cookies = [insecure_cookie]
    session.get.return_value = resp

    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    cookie_vulns = [v for v in vulns if "PHPSESSID" in v.name]
    assert len(cookie_vulns) == 1
    assert cookie_vulns[0].severity.name == "HIGH"


@patch("modules.cookie_scanner.requests.Session")
def test_detecta_cookie_sin_secure(MockSession, scanner):
    """Cookie sin Secure pero con HttpOnly → vulnerabilidad MEDIUM."""
    session = MockSession.return_value
    resp = MagicMock()

    insecure_cookie = _make_cookie("session_id", secure=False, httponly=True)
    session.cookies = [insecure_cookie]
    session.get.return_value = resp

    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    cookie_vulns = [v for v in vulns if "session_id" in v.name]
    assert len(cookie_vulns) == 1
    assert cookie_vulns[0].severity.name == "MEDIUM"


@patch("modules.cookie_scanner.requests.Session")
def test_sin_cookies_no_reporta(MockSession, scanner):
    """Sin cookies en la respuesta → sin hallazgos."""
    session = MockSession.return_value
    resp = MagicMock()

    session.cookies = []
    session.get.return_value = resp

    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.cookie_scanner.requests.Session")
def test_cookie_segura_no_reporta(MockSession, scanner):
    """Cookie con Secure y HttpOnly → sin hallazgos."""
    session = MockSession.return_value
    resp = MagicMock()

    secure_cookie = _make_cookie("token", secure=True, httponly=True)
    session.cookies = [secure_cookie]
    session.get.return_value = resp

    target = Target(url="http://localhost")
    vulns = scanner.run(target)
    assert len(vulns) == 0
