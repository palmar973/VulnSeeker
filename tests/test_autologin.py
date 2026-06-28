"""
Tests unitarios: Auto-login DVWA (core/engine.py :: _check_and_perform_autologin).

Valida los tres caminos principales con peticiones HTTP simuladas (sin red real):
  1. El objetivo no es DVWA -> no se modifica la sesión.
  2. DVWA detectado y login exitoso -> se actualizan las cookies del motor.
  3. Sesión existente válida -> se omite el re-login (no se abre Session).
"""
from unittest.mock import patch, MagicMock
from core.engine import VulnSeekerEngine


def _resp(text="", status=200, url=""):
    """Construye una respuesta HTTP simulada."""
    m = MagicMock()
    m.text = text
    m.status_code = status
    m.url = url
    return m


def test_autologin_ignora_objetivo_no_dvwa():
    """Si /login.php no es DVWA, el motor no debe tocar las cookies."""
    engine = VulnSeekerEngine(enable_subdomains=False)

    with patch("requests.get", return_value=_resp(text="<html>Sitio normal</html>", status=200)):
        engine._check_and_perform_autologin("http://normal.com")

    assert not engine.config.get("cookies")


def test_autologin_dvwa_login_exitoso_actualiza_cookies():
    """DVWA detectado + login correcto debe poblar config['cookies']."""
    engine = VulnSeekerEngine(enable_subdomains=False)

    # Detección inicial (requests.get sobre login.php) -> marcador DVWA
    def get_side_effect(url, **kw):
        if "login.php" in url:
            return _resp(text="Login :: Damn Vulnerable Web Application", status=200)
        return _resp(text="", status=200)

    # Sesión autenticada simulada
    session = MagicMock()

    def sess_get(url, **kw):
        if "setup.php" in url:
            return _resp(text="<html>BD ya inicializada</html>", status=200)
        if "login.php" in url:
            return _resp(text='<input name="user_token" value="tok123">', status=200)
        if "security.php" in url:
            return _resp(text='<input name="user_token" value="sectok">', status=200)
        return _resp(text="", status=200)

    def sess_post(url, **kw):
        if "login.php" in url:
            # Login OK: redirige fuera de login.php y sin formulario de login
            return _resp(text="Welcome to the password protected area admin",
                         status=200, url="http://dvwa/index.php")
        return _resp(text="ok", status=200, url=url)

    session.get.side_effect = sess_get
    session.post.side_effect = sess_post
    session.cookies.get_dict.return_value = {"PHPSESSID": "abc123", "security": "low"}

    with patch("requests.get", side_effect=get_side_effect), \
         patch("requests.Session", return_value=session):
        engine._check_and_perform_autologin("http://dvwa/index.php")

    assert engine.config.get("cookies", {}).get("PHPSESSID") == "abc123"
    assert engine.config["cookies"].get("security") == "low"


def test_autologin_omite_si_sesion_existente_valida():
    """Con una sesión válida ya configurada no se debe re-loguear."""
    engine = VulnSeekerEngine(config={"cookies": {"PHPSESSID": "exist"}})

    def get_side_effect(url, **kw):
        if "login.php" in url:
            return _resp(text="Login :: Damn Vulnerable Web Application", status=200)
        if "index.php" in url:
            # 200 sin formulario de login => sesión vigente
            return _resp(text="<html>Welcome admin (logged in)</html>", status=200)
        return _resp(text="", status=200)

    with patch("requests.get", side_effect=get_side_effect), \
         patch("requests.Session") as mock_session:
        engine._check_and_perform_autologin("http://dvwa/")

    # No debe abrir una nueva Session para re-loguearse
    mock_session.assert_not_called()


def test_autologin_no_propaga_excepciones():
    """Un fallo de red durante el chequeo no debe romper el escaneo."""
    engine = VulnSeekerEngine(enable_subdomains=False)

    with patch("requests.get", side_effect=ConnectionError("sin red")):
        # No debe lanzar; simplemente retorna
        engine._check_and_perform_autologin("http://inalcanzable.local")

    assert not engine.config.get("cookies")
