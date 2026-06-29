import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.path_fuzzer import PathFuzzer


@pytest.fixture
def fuzzer():
    return PathFuzzer()


def _resp(status, body=b""):
    return MagicMock(status_code=status, content=body)


def _make_get(exposed_paths, body=b"contenido sensible"):
    """Simula un servidor con 404 real: solo los paths indicados devuelven 200.
    Las sondas aleatorias del baseline (rutas inexistentes) devuelven 404, por lo
    que NO se detecta catch-all y el fuzzer opera normalmente."""
    def _get(url, *args, **kwargs):
        if any(p.rstrip("/") in url for p in exposed_paths):
            return _resp(200, body)
        return _resp(404, b"Not Found")
    return _get


@patch("modules.path_fuzzer.requests.get")
def test_detecta_env_expuesto(mock_get, fuzzer):
    """.env accesible (200) en un servidor con 404 real → CRITICAL."""
    mock_get.side_effect = _make_get([".env"])
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    env_vulns = [v for v in vulns if ".env" in v.name]
    assert len(env_vulns) >= 1
    assert env_vulns[0].severity.name == "CRITICAL"


@patch("modules.path_fuzzer.requests.get")
def test_no_reporta_404(mock_get, fuzzer):
    """Todos los paths devuelven 404 → sin alertas."""
    mock_get.return_value = _resp(404, b"Not Found")
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    assert len(vulns) == 0


@patch("modules.path_fuzzer.requests.get")
def test_detecta_git_expuesto(mock_get, fuzzer):
    """.git/HEAD accesible en servidor con 404 real → CRITICAL."""
    mock_get.side_effect = _make_get([".git"])
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    git_vulns = [v for v in vulns if ".git" in v.name]
    assert len(git_vulns) >= 1


@patch("modules.path_fuzzer.requests.get")
def test_catch_all_no_genera_falsos_positivos(mock_get, fuzzer):
    """Servidor catch-all (200 a TODO, mismo cuerpo, típico de SPA): el fuzzer NO
    debe reportar ningún archivo como expuesto, porque el 200 no implica existencia."""
    spa_body = b"<!doctype html><html><app-root></app-root></html>" * 20
    mock_get.return_value = _resp(200, spa_body)
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    assert vulns == []


@patch("modules.path_fuzzer.requests.get")
def test_catch_all_si_reporta_contenido_distinto(mock_get, fuzzer):
    """En un servidor catch-all, un recurso que SÍ existe (cuerpo claramente distinto
    al catch-all) debe seguir reportándose: no todo se descarta a ciegas."""
    spa_body = b"<!doctype html><html><app-root></app-root></html>" * 20

    def _get(url, *args, **kwargs):
        # robots.txt existe de verdad: cuerpo corto y distinto del index catch-all
        if "robots.txt" in url:
            return _resp(200, b"User-agent: *\nDisallow: /admin")
        return _resp(200, spa_body)

    mock_get.side_effect = _get
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    nombres = [v.name for v in vulns]
    assert any("robots.txt" in n for n in nombres)
    # y NO debe reportar los archivos sensibles inexistentes servidos por el catch-all
    assert not any(".env" in n for n in nombres)
