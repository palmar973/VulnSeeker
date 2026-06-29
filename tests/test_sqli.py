"""
Tests unitarios: SQLi Module (modules/sqli_module.py).
Valida la detección de errores SQL en respuestas HTTP simuladas.
"""
import re
from unittest.mock import patch, MagicMock
from modules.sqli_module import SQLInjectionScanner
from core.models import Target, PageElement, Severity


def test_detecta_error_mysql_en_respuesta():
    """Debe reportar SQLi cuando la respuesta contiene un error MySQL."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/page?id=1")

    mock_resp = MagicMock()
    mock_resp.text = "You have an error in your SQL syntax near '1'' at line 1"

    with patch("modules.sqli_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH
    assert "SQL" in vulns[0].name


def test_no_reporta_sqli_en_respuesta_limpia():
    """No debe reportar SQLi si la respuesta no contiene errores de BD."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/page?id=1")

    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Página normal sin errores</body></html>"

    with patch("modules.sqli_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_ignora_urls_sin_parametros():
    """URLs sin query params no deben ser analizadas para SQLi."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/index.html")

    vulns = scanner.run(target)
    assert len(vulns) == 0


def test_detecta_sqli_en_form_post():
    """Debe detectar SQLi en formularios POST con campos inyectables."""
    scanner = SQLInjectionScanner()
    element = PageElement(
        url="http://test.com/login.php",
        method="POST",
        params={"username": "admin", "password": "test"},
        is_form=True
    )
    target = Target(url="http://test.com/login.php", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "You have an error in your SQL syntax"

    with patch("modules.sqli_module.requests.post", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert "POST" in vulns[0].name
    assert vulns[0].severity == Severity.HIGH


def test_replace_strategy_detecta_sqli():
    """La estrategia de reemplazo completo debe detectar SQLi también."""
    scanner = SQLInjectionScanner()
    target = Target(url="http://test.com/page?id=5")

    call_count = 0

    def mock_get_side_effect(url, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        # La concatenación (id=5') no dispara error, pero el reemplazo (id=') sí
        if "id=%27" in url or "id='" in url:
            resp.text = "Warning: mysql_fetch_array()"
        else:
            resp.text = "<html>OK</html>"
        return resp

    with patch("modules.sqli_module.requests.get", side_effect=mock_get_side_effect):
        vulns = scanner.run(target)

    assert len(vulns) >= 1


def test_detecta_sqli_en_form_get():
    """Debe detectar SQLi en formularios GET (params enviados como query string)."""
    scanner = SQLInjectionScanner()
    element = PageElement(
        url="http://test.com/vulnerabilities/sqli/",
        method="GET",
        params={"id": "", "Submit": "Submit"},
        is_form=True
    )
    target = Target(url="http://test.com/vulnerabilities/sqli/", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "You have an error in your SQL syntax"

    with patch("modules.sqli_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) >= 1
    assert "GET" in vulns[0].name
    assert vulns[0].severity == Severity.HIGH


def test_no_reporta_sqli_en_form_get_limpio():
    """Un formulario GET sin errores de BD no debe reportar SQLi."""
    scanner = SQLInjectionScanner()
    element = PageElement(
        url="http://test.com/search",
        method="GET",
        params={"q": "test"},
        is_form=True
    )
    target = Target(url="http://test.com/search", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "<html>resultados de búsqueda</html>"

    with patch("modules.sqli_module.requests.get", return_value=mock_resp):
        vulns = scanner.run(target)

    assert len(vulns) == 0


def test_form_get_inyecta_payload_en_query_string():
    """El fuzzing de formularios GET debe construir la URL con el payload en la query."""
    scanner = SQLInjectionScanner()
    element = PageElement(
        url="http://test.com/page",
        method="GET",
        params={"id": "1"},
        is_form=True
    )
    target = Target(url="http://test.com/page", elements=[element])

    urls_llamadas = []

    def mock_get(url, **kwargs):
        urls_llamadas.append(url)
        resp = MagicMock()
        resp.text = "<html>ok</html>"
        return resp

    with patch("modules.sqli_module.requests.get", side_effect=mock_get):
        scanner.run(target)

    # La URL atacada debe llevar el parámetro 'id' inyectado en la query string
    assert urls_llamadas, "No se realizó ninguna petición"
    assert all("http://test.com/page?" in u for u in urls_llamadas)
    assert any("id=" in u for u in urls_llamadas)


# --- SQLi en APIs REST con cuerpo JSON ---

def test_detecta_sqli_en_json_body():
    """Debe detectar SQLi al inyectar en un campo de un cuerpo JSON (API REST)."""
    scanner = SQLInjectionScanner(enable_blind=False)
    element = PageElement(
        url="http://api.test/rest/user/login",
        method="POST",
        params={"email": "a@a.com", "password": "x"},
        body_type="json",
    )
    target = Target(url="http://api.test/rest/user/login", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "Error: SQLITE_ERROR: unrecognized token near \"'\""

    with patch("modules.sqli_module.requests.post", return_value=mock_resp):
        vulns = scanner.run(target)

    assert any("JSON" in v.name for v in vulns)
    assert vulns[0].severity == Severity.HIGH


def test_detecta_sqli_json_firma_sequelize():
    """El stack trace de un ORM (Sequelize sobre SQLite) debe contar como error SQL."""
    scanner = SQLInjectionScanner(enable_blind=False)
    element = PageElement(
        url="http://api.test/rest/user/login",
        method="POST",
        params={"email": "a@a.com", "password": "x"},
        body_type="json",
    )
    target = Target(url="http://api.test/rest/user/login", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = "at /app/node_modules/sequelize/lib/dialects/sqlite/query.js:185:27"

    with patch("modules.sqli_module.requests.post", return_value=mock_resp):
        vulns = scanner.run(target)

    assert any("JSON" in v.name for v in vulns)


def test_no_reporta_sqli_json_limpio():
    """Una respuesta JSON sin errores de BD no debe reportar SQLi."""
    scanner = SQLInjectionScanner(enable_blind=False)
    element = PageElement(
        url="http://api.test/rest/user/login",
        method="POST",
        params={"email": "a@a.com", "password": "x"},
        body_type="json",
    )
    target = Target(url="http://api.test/rest/user/login", elements=[element])

    mock_resp = MagicMock()
    mock_resp.text = '{"authentication":{"token":"abc"}}'

    with patch("modules.sqli_module.requests.post", return_value=mock_resp):
        vulns = scanner.run(target)

    assert vulns == []


def test_json_envia_content_type_json():
    """El fuzzing de cuerpo JSON debe enviarse como application/json."""
    scanner = SQLInjectionScanner(enable_blind=False)
    element = PageElement(
        url="http://api.test/rest/user/login",
        method="POST",
        params={"email": "a@a.com"},
        body_type="json",
    )
    target = Target(url="http://api.test/rest/user/login", elements=[element])

    capturado = {}

    def mock_post(url, **kwargs):
        capturado.update(kwargs)
        return MagicMock(text="<html>ok</html>")

    with patch("modules.sqli_module.requests.post", side_effect=mock_post):
        scanner.run(target)

    assert capturado.get("headers", {}).get("Content-Type") == "application/json"
    assert "json" in capturado  # se envió cuerpo JSON (no data form-urlencoded)


# --- SQLi ciego basado en tiempo (Blind Time-Based) ---

def test_detecta_blind_sqli_time_based():
    """Si inyectar un retardo controlado demora la respuesta de forma proporcional,
    el parámetro es vulnerable a SQLi ciego (time-based)."""
    scanner = SQLInjectionScanner(enable_blind=True)
    element = PageElement(url="http://test.com/sqli_blind/", method="GET",
                          params={"id": "1", "Submit": "Submit"}, is_form=True)
    target = Target(url="http://test.com/sqli_blind/", elements=[element])

    def fake_timed(method, parsed_url, param_name, value, base_params, headers):
        # Respuesta rápida salvo cuando el valor inyecta un SLEEP(n): tarda n segundos.
        m = re.search(r"SLEEP\((\d+)\)", value)
        return 0.1 + (float(m.group(1)) if m else 0.0)

    with patch.object(scanner, "_timed_inject", side_effect=fake_timed), \
         patch("modules.sqli_module.requests.get", return_value=MagicMock(text="ok")):
        vulns = scanner.run(target)

    blind = [v for v in vulns if "Blind" in v.name]
    assert len(blind) >= 1
    assert blind[0].severity == Severity.HIGH


def test_no_reporta_blind_sin_retardo():
    """Sin diferencia de tiempo entre baseline y payload, no debe reportar (anti-FP)."""
    scanner = SQLInjectionScanner(enable_blind=True)
    element = PageElement(url="http://test.com/search", method="GET",
                          params={"q": "x"}, is_form=True)
    target = Target(url="http://test.com/search", elements=[element])

    with patch.object(scanner, "_timed_inject", return_value=0.1), \
         patch("modules.sqli_module.requests.get", return_value=MagicMock(text="ok")):
        vulns = scanner.run(target)

    assert [v for v in vulns if "Blind" in v.name] == []


def test_blind_desactivado_no_ejecuta():
    """Con enable_blind=False la detección time-based no debe ejecutarse."""
    scanner = SQLInjectionScanner(enable_blind=False)
    element = PageElement(url="http://test.com/sqli_blind/", method="GET",
                          params={"id": "1"}, is_form=True)
    target = Target(url="http://test.com/sqli_blind/", elements=[element])

    llamado = {"blind": False}

    def fake_timed(*args, **kwargs):
        llamado["blind"] = True
        return 9.0

    with patch.object(scanner, "_timed_inject", side_effect=fake_timed), \
         patch("modules.sqli_module.requests.get", return_value=MagicMock(text="ok")):
        vulns = scanner.run(target)

    assert llamado["blind"] is False
    assert [v for v in vulns if "Blind" in v.name] == []


def test_blind_no_duplica_si_error_based_ya_detecto():
    """Si el error-based ya marcó la URL, el blind no debe re-evaluarla (sin duplicar)."""
    scanner = SQLInjectionScanner(enable_blind=True)
    element = PageElement(url="http://test.com/sqli/", method="GET",
                          params={"id": "1", "Submit": "Submit"}, is_form=True)
    target = Target(url="http://test.com/sqli/", elements=[element])

    # El error-based detecta (respuesta con error SQL) → la URL queda marcada.
    err = MagicMock(text="You have an error in your SQL syntax")

    llamado = {"blind": False}

    def fake_timed(*args, **kwargs):
        llamado["blind"] = True
        return 9.0

    with patch("modules.sqli_module.requests.get", return_value=err), \
         patch.object(scanner, "_timed_inject", side_effect=fake_timed):
        vulns = scanner.run(target)

    assert any("Error Based" in v.name for v in vulns)
    assert llamado["blind"] is False  # no se ejecuta blind sobre una URL ya detectada
    assert [v for v in vulns if "Blind" in v.name] == []

