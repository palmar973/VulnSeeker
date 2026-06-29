"""
Tests del descubridor de endpoints de API sin navegador (core/api_discovery.py).
Cubre la capa spec-driven (OpenAPI/Swagger), la extracción de JS, el sondeo de
endpoints REST canónicos (búsqueda/login) y la ausencia de regresión en
aplicaciones server-rendered (sin API → sin endpoints).
"""
import json
from unittest.mock import patch, MagicMock
from core.api_discovery import ApiEndpointDiscovery


def _resp(status=200, text="", content_type="text/html"):
    m = MagicMock(status_code=status, text=text)
    m.headers = {"Content-Type": content_type}
    m.json = lambda: json.loads(text)
    return m


def _no_post(url, *a, **k):
    """POST por defecto: 404 (los probes de login no añaden nada)."""
    return _resp(status=404, text="Not Found")


def test_extrae_endpoints_de_javascript():
    """Debe extraer rutas /api/ y /rest/ del bundle JS y marcar /search como inyectable."""
    index_html = '<html><head><script src="main.js"></script></head><body></body></html>'
    bundle = """
        const a = this.http.get('/rest/products/search?q='+x);
        this.http.get('api/Products'); fetch("/rest/user/whoami");
        const tpl = `/rest/products/${id}`;  // plantilla: debe ignorarse
    """

    def fake_get(url, *a, **k):
        if url.endswith("main.js"):
            return _resp(text=bundle)
        if url.rstrip("/").endswith("3000") or url.endswith("/"):
            return _resp(text=index_html)
        return _resp(status=404)

    disc = ApiEndpointDiscovery("http://localhost:3000")
    with patch("core.api_discovery.requests.get", side_effect=fake_get), \
         patch("core.api_discovery.requests.post", side_effect=_no_post):
        els = disc.discover()

    urls = {e.url for e in els}
    assert "http://localhost:3000/rest/products/search" in urls
    assert "http://localhost:3000/api/Products" in urls
    assert "http://localhost:3000/rest/user/whoami" in urls
    # La plantilla dinámica /rest/products/${id} NO debe colarse
    assert not any("$" in u or "{" in u for u in urls)
    # El endpoint de búsqueda debe quedar inyectable (?q=)
    search = [e for e in els if e.url.endswith("/search")][0]
    assert search.params.get("q") is not None and search.is_form


def test_parsea_spec_openapi():
    """Si la app publica una spec OpenAPI válida, deben derivarse sus operaciones."""
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {"get": {"parameters": [{"in": "query", "name": "limit"}]}},
            "/login": {"post": {}},
        },
    }
    spec_text = json.dumps(spec)

    def fake_get(url, *a, **k):
        if url.endswith("openapi.json"):
            return _resp(text=spec_text, content_type="application/json")
        if url.endswith("/"):  # index sin scripts → capa JS vacía
            return _resp(text="<html></html>")
        return _resp(status=404)

    disc = ApiEndpointDiscovery("http://api.local")
    with patch("core.api_discovery.requests.get", side_effect=fake_get), \
         patch("core.api_discovery.requests.post", side_effect=_no_post):
        els = disc.discover()

    pares = {(e.url, e.method) for e in els}
    assert ("http://api.local/users", "GET") in pares
    assert ("http://api.local/login", "POST") in pares
    users = [e for e in els if e.url.endswith("/users")][0]
    assert "limit" in users.params


def test_spec_catch_all_no_se_confunde():
    """Un servidor catch-all que devuelve HTML 200 en /openapi.json NO debe tomarse
    como spec (validación de content-type + estructura)."""
    def fake_get(url, *a, **k):
        return _resp(text="<html><app-root></app-root></html>")

    disc = ApiEndpointDiscovery("http://spa.local")
    with patch("core.api_discovery.requests.get", side_effect=fake_get), \
         patch("core.api_discovery.requests.post", side_effect=_no_post):
        els = disc.discover()
    assert els == []


def test_app_sin_api_no_descubre_nada():
    """App server-rendered (sin spec ni rutas /api en JS, 404 real) → sin endpoints."""
    index_html = '<html><head><script src="app.js"></script></head></html>'

    def fake_get(url, *a, **k):
        if url.endswith("app.js"):
            return _resp(text="function x(){ return document.body; }")
        if url.endswith("/"):
            return _resp(text=index_html)
        return _resp(status=404)  # incluido el probe GET de búsqueda

    disc = ApiEndpointDiscovery("http://classic.local")
    with patch("core.api_discovery.requests.get", side_effect=fake_get), \
         patch("core.api_discovery.requests.post", side_effect=_no_post):
        els = disc.discover()
    assert els == []


def test_probe_descubre_login_por_error_de_aplicacion():
    """Un /rest/user/login que responde 401 (no JSON, no SPA) debe añadirse como
    POST JSON con campos de ataque (email/password)."""
    def fake_get(url, *a, **k):
        if "search" in url:
            return _resp(status=200, text='{"status":"success"}', content_type="application/json")
        if url.endswith("/"):
            return _resp(text="<html></html>")
        return _resp(status=404)

    def fake_post(url, *a, **k):
        if url.endswith("/rest/user/login"):
            return _resp(status=401, text="Invalid email or password.")
        return _resp(status=404)

    disc = ApiEndpointDiscovery("http://juice.local")
    with patch("core.api_discovery.requests.get", side_effect=fake_get), \
         patch("core.api_discovery.requests.post", side_effect=fake_post):
        els = disc.discover()

    login = [e for e in els if e.url.endswith("/rest/user/login")]
    assert login, "El probe de login no descubrió el endpoint"
    assert login[0].method == "POST"
    assert login[0].body_type == "json"
    assert "email" in login[0].params and "password" in login[0].params

    search = [e for e in els if e.url.endswith("/rest/products/search")]
    assert search and search[0].params.get("q") is not None


def test_probe_no_se_activa_con_404():
    """Si los endpoints canónicos devuelven 404 (no existen), no se añaden (anti-FP)."""
    def fake_get(url, *a, **k):
        if url.endswith("/"):
            return _resp(text="<html></html>")
        return _resp(status=404)

    def fake_post(url, *a, **k):
        return _resp(status=404, text="Cannot POST")

    disc = ApiEndpointDiscovery("http://dvwa.local")
    with patch("core.api_discovery.requests.get", side_effect=fake_get), \
         patch("core.api_discovery.requests.post", side_effect=fake_post):
        els = disc.discover()
    assert els == []
