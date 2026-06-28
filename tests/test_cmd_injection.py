"""
Tests unitarios: Command Injection Module (modules/cmd_injection.py).
Valida que accede correctamente a los params vía target.elements.
"""
from unittest.mock import patch, MagicMock
from modules.cmd_injection import CommandInjectionScanner
from core.models import Target, PageElement, Severity


def test_accede_a_params_via_elements():
    """Debe leer parámetros desde target.elements[0].params sin error."""
    scanner = CommandInjectionScanner()
    element = PageElement(url="http://test.com/ping", params={"ip": "127.0.0.1"})
    target = Target(url="http://test.com/ping", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "Respuesta normal sin evidencia de RCE"

    with patch("modules.cmd_injection.requests.Session") as mock_session:
        mock_session.return_value.get.return_value = mock_resp
        mock_session.return_value.post.return_value = mock_resp
        vulns = scanner.run(target)

    # No debe haber crash por AttributeError
    assert isinstance(vulns, list)


def test_detecta_rce_en_respuesta():
    """Debe reportar RCE cuando la evidencia aparece tras el ataque y no en el baseline."""
    scanner = CommandInjectionScanner()
    element = PageElement(url="http://test.com/ping", params={"ip": "127.0.0.1"})
    target = Target(url="http://test.com/ping", elements=[element])

    limpia = MagicMock(text="Respuesta normal, sin evidencia")
    rce = MagicMock(text="root:x:0:0:root:/root:/bin/bash")

    llamadas = {"n": 0}

    def get_side_effect(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else rce  # 1ª llamada = baseline limpio

    with patch("modules.cmd_injection.requests.Session") as mock_session:
        mock_session.return_value.get.side_effect = get_side_effect
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "Command Injection" in vulns[0].name


def test_no_reporta_rce_si_evidencia_ya_en_baseline():
    """Si 'root:x:0:0' ya estaba en la respuesta base (no lo causó el payload), no es RCE."""
    scanner = CommandInjectionScanner()
    element = PageElement(url="http://test.com/ping", params={"ip": "127.0.0.1"})
    target = Target(url="http://test.com/ping", elements=[element])

    # Baseline y ataque devuelven lo mismo: la evidencia ya estaba presente.
    resp = MagicMock(text="root:x:0:0:root:/root:/bin/bash")

    with patch("modules.cmd_injection.requests.Session") as mock_session:
        mock_session.return_value.get.return_value = resp
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_funciona_sin_elements():
    """Debe funcionar sin error incluso si target.elements está vacío."""
    scanner = CommandInjectionScanner()
    target = Target(url="http://test.com/page")

    mock_resp = MagicMock()
    mock_resp.text = "Normal response"

    with patch("modules.cmd_injection.requests.Session") as mock_session:
        mock_session.return_value.get.return_value = mock_resp
        mock_session.return_value.post.return_value = mock_resp
        vulns = scanner.run(target)

    assert isinstance(vulns, list)
