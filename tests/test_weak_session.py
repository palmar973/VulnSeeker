import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.weak_session_auditor import WeakSessionAuditor


@pytest.fixture
def auditor():
    return WeakSessionAuditor()


def _make_cookie(name="PHPSESSID", value="abc123def456ghi789", rest=None):
    cookie = MagicMock()
    cookie.name = name
    cookie.value = value
    cookie._rest = rest or {}
    return cookie


def _mock_session_with_cookies(cookies):
    """Creates a mock Session whose .cookies is iterable and truthy."""
    session = MagicMock()
    cookie_jar = MagicMock()
    cookie_jar.__iter__ = MagicMock(return_value=iter(cookies))
    cookie_jar.__bool__ = MagicMock(return_value=bool(cookies))
    session.cookies = cookie_jar
    return session


@patch("modules.weak_session_auditor.requests.Session")
def test_detecta_token_corto(MockSession, auditor):
    """Token de sesión < 16 chars → Short Session Token."""
    cookie = _make_cookie(value="short123")
    MockSession.return_value = _mock_session_with_cookies([cookie])

    target = Target(url="http://localhost/app")
    vulns = auditor.run(target)
    short_vulns = [v for v in vulns if v.name == "Short Session Token"]
    assert len(short_vulns) == 1
    assert short_vulns[0].severity.name == "MEDIUM"


@patch("modules.weak_session_auditor.requests.Session")
def test_detecta_baja_entropia(MockSession, auditor):
    """Token con valor repetitivo (baja entropía) → alerta."""
    cookie = _make_cookie(value="aaaaaaaaaaaaaaaaaaaaa")
    MockSession.return_value = _mock_session_with_cookies([cookie])

    target = Target(url="http://localhost/app")
    vulns = auditor.run(target)
    entropy_vulns = [v for v in vulns if v.name == "Low Session Token Entropy"]
    assert len(entropy_vulns) == 1
    assert entropy_vulns[0].severity.name == "HIGH"


@patch("modules.weak_session_auditor.requests.Session")
def test_no_alerta_token_fuerte(MockSession, auditor):
    """Token largo y aleatorio → sin alerta de entropía ni longitud."""
    cookie = _make_cookie(value="a8f3b2c1d9e7x4k5m6n0p3q8r1s2t7u9")
    MockSession.return_value = _mock_session_with_cookies([cookie])

    target = Target(url="http://localhost/app")
    vulns = auditor.run(target)
    entropy_vulns = [v for v in vulns if v.name == "Low Session Token Entropy"]
    short_vulns = [v for v in vulns if v.name == "Short Session Token"]
    assert len(entropy_vulns) == 0
    assert len(short_vulns) == 0


@patch("modules.weak_session_auditor.requests.Session")
def test_detecta_samesite_faltante(MockSession, auditor):
    """Cookie de sesión sin SameSite → Missing SameSite Attribute."""
    cookie = _make_cookie(value="a8f3b2c1d9e7x4k5m6n0")
    MockSession.return_value = _mock_session_with_cookies([cookie])

    target = Target(url="http://localhost/app")
    vulns = auditor.run(target)
    samesite_vulns = [v for v in vulns if v.name == "Missing SameSite Attribute"]
    assert len(samesite_vulns) == 1


@patch("modules.weak_session_auditor.requests.Session")
def test_ignora_cookies_no_sesion(MockSession, auditor):
    """Cookies que no son de sesión (ej: analytics) se ignoran."""
    cookie = _make_cookie(name="_ga", value="GA1.2.12345.67890")
    MockSession.return_value = _mock_session_with_cookies([cookie])

    target = Target(url="http://localhost/app")
    vulns = auditor.run(target)
    assert len(vulns) == 0


def test_entropia_calculada_correctamente(auditor):
    """Verificar que el cálculo de entropía de Shannon es correcto."""
    assert auditor._calculate_entropy("aaaa") == 0.0
    entropy = auditor._calculate_entropy("abcdefghij1234567890")
    assert entropy > 3.5
