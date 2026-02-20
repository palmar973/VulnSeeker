import pytest
from unittest.mock import patch, MagicMock
from core.models import Target, PageElement
from modules.brute_force_detector import BruteForceDetector


@pytest.fixture
def detector():
    return BruteForceDetector()


def _make_target(url="http://localhost/login.php", method="POST",
                 params=None, is_form=True):
    params = params or {"username": "", "password": "", "Login": "Login"}
    element = PageElement(url=url, method=method, params=params, is_form=is_form)
    return Target(url=url, method=method, elements=[element])


@patch("modules.brute_force_detector.requests.post")
def test_detecta_login_sin_captcha(mock_post, detector):
    """Un form de login sin CAPTCHA genera vulnerabilidad HIGH."""
    mock_resp = MagicMock(status_code=200, headers={})
    mock_post.return_value = mock_resp
    target = _make_target()
    vulns = detector.run(target)
    captcha_vulns = [v for v in vulns if v.name == "Login Without CAPTCHA"]
    assert len(captcha_vulns) == 1
    assert captcha_vulns[0].severity.name == "HIGH"


@patch("modules.brute_force_detector.requests.post")
def test_no_reporta_si_tiene_captcha(mock_post, detector):
    """Un form con campo CAPTCHA NO genera alerta de captcha."""
    mock_resp = MagicMock(status_code=200, headers={})
    mock_post.return_value = mock_resp
    target = _make_target(params={
        "username": "", "password": "", "g-recaptcha-response": ""
    })
    vulns = detector.run(target)
    captcha_vulns = [v for v in vulns if v.name == "Login Without CAPTCHA"]
    assert len(captcha_vulns) == 0


@patch("modules.brute_force_detector.requests.post")
def test_detecta_sin_rate_limiting(mock_post, detector):
    """3 POSTs sin recibir 429 → No Rate Limiting."""
    mock_resp = MagicMock(status_code=200, headers={})
    mock_post.return_value = mock_resp
    target = _make_target()
    vulns = detector.run(target)
    rate_vulns = [v for v in vulns if v.name == "No Rate Limiting"]
    assert len(rate_vulns) == 1


@patch("modules.brute_force_detector.requests.post")
def test_no_reporta_rate_limit_si_429(mock_post, detector):
    """Si el server responde 429, no hay vuln de rate limiting."""
    mock_resp = MagicMock(status_code=429, headers={"Retry-After": "30"})
    mock_post.return_value = mock_resp
    target = _make_target()
    vulns = detector.run(target)
    rate_vulns = [v for v in vulns if v.name == "No Rate Limiting"]
    assert len(rate_vulns) == 0


def test_ignora_formularios_sin_password(detector):
    """Un form sin campo password no es un login → sin vulns."""
    target = _make_target(params={"search": "", "q": ""})
    vulns = detector.run(target)
    assert len(vulns) == 0


def test_ignora_formularios_get(detector):
    """Formularios GET nunca son login forms para brute force."""
    target = _make_target(method="GET")
    vulns = detector.run(target)
    assert len(vulns) == 0
