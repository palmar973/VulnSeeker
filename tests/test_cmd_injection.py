"""
Tests unitarios: Command Injection Module (modules/cmd_injection.py).

Cubre la detección basada en contenido (con guarda de baseline anti falso
positivo) y la detección ciega basada en tiempo (con confirmación proporcional).
El envío HTTP vive ahora en modules/injection_points.py, así que los mocks se
aplican sobre modules.injection_points.requests.
"""
from unittest.mock import patch, MagicMock

from modules.cmd_injection import CommandInjectionScanner
from core.models import Target, PageElement, Severity


def test_accede_a_params_via_elements():
    """Debe leer parámetros desde un formulario (target.elements) sin error."""
    scanner = CommandInjectionScanner(enable_blind=False)
    element = PageElement(url="http://test.com/ping", method="POST",
                          params={"ip": "127.0.0.1"}, is_form=True)
    target = Target(url="http://test.com/ping", elements=[element])

    clean = MagicMock(text="Respuesta normal sin evidencia de RCE")
    with patch("modules.injection_points.requests.post", return_value=clean):
        vulns = scanner.run(target)

    assert isinstance(vulns, list)


def test_detecta_rce_en_respuesta():
    """Reporta RCE cuando la evidencia aparece tras el ataque y no en el baseline."""
    scanner = CommandInjectionScanner(enable_blind=False)
    target = Target(url="http://test.com/ping?ip=127.0.0.1")

    limpia = MagicMock(text="pong normal, sin evidencia")
    rce = MagicMock(text="uid=0(root) gid=0(root) groups=0(root)")

    llamadas = {"n": 0}

    def side(url, **kwargs):
        llamadas["n"] += 1
        return limpia if llamadas["n"] == 1 else rce  # 1ª llamada = baseline limpio

    with patch("modules.injection_points.requests.get", side_effect=side):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "Command Injection" in vulns[0].name


def test_no_reporta_rce_si_evidencia_ya_en_baseline():
    """Si 'root' ya estaba en la respuesta base (no lo causó el payload), no es RCE."""
    scanner = CommandInjectionScanner(enable_blind=False)
    target = Target(url="http://test.com/ping?ip=127.0.0.1")

    resp = MagicMock(text="root:x:0:0:root:/root:/bin/bash")  # baseline == ataque
    with patch("modules.injection_points.requests.get", return_value=resp):
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_funciona_sin_elements():
    """Debe funcionar (vía nombres de fallback) aunque no haya params ni formulario."""
    scanner = CommandInjectionScanner(enable_blind=False)
    target = Target(url="http://test.com/page")

    clean = MagicMock(text="Normal response")
    with patch("modules.injection_points.requests.get", return_value=clean):
        vulns = scanner.run(target)

    assert isinstance(vulns, list)


def _fake_timed_factory(t_confirm):
    """Devuelve un _timed simulado: baseline rápido, retardo 'd' lento y retardo
    '2d' con el valor t_confirm (para simular escalado real o jitter que no escala)."""
    def fake_timed(pt, value, headers):
        if any(f"{cmd} 10" in value for cmd in ("sleep", "-c", "-n")):
            return t_confirm          # respuesta al retardo doble (2d = 10s)
        if any(f"{cmd} 5" in value for cmd in ("sleep", "-c", "-n")):
            return 5.2                # respuesta al retardo simple (d = 5s)
        return 0.1                    # baseline benigno
    return fake_timed


def test_detecta_rce_ciego_time_based():
    """Si el retardo escala proporcionalmente (5s y 10s), reporta RCE ciego."""
    scanner = CommandInjectionScanner(enable_blind=True)
    target = Target(url="http://test.com/ping?ip=127.0.0.1")

    clean = MagicMock(text="pong")  # sin evidencia reflejada -> pasa a la prueba ciega
    with patch("modules.injection_points.requests.get", return_value=clean), \
         patch.object(scanner, "_timed", side_effect=_fake_timed_factory(10.3)):
        vulns = scanner.run(target)

    ciegos = [v for v in vulns if "Blind Time-Based" in v.name]
    assert len(ciegos) >= 1
    assert ciegos[0].severity == Severity.CRITICAL


def test_no_reporta_ciego_si_el_retardo_no_escala():
    """Un pico puntual a 5s que NO se confirma al duplicar el retardo no es RCE
    (descarta lentitudes de red = evita falsos positivos)."""
    scanner = CommandInjectionScanner(enable_blind=True)
    target = Target(url="http://test.com/ping?ip=127.0.0.1")

    clean = MagicMock(text="pong")
    with patch("modules.injection_points.requests.get", return_value=clean), \
         patch.object(scanner, "_timed", side_effect=_fake_timed_factory(0.2)):
        vulns = scanner.run(target)

    ciegos = [v for v in vulns if "Blind Time-Based" in v.name]
    assert len(ciegos) == 0
