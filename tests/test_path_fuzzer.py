import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.path_fuzzer import PathFuzzer


@pytest.fixture
def fuzzer():
    return PathFuzzer()


@patch("modules.path_fuzzer.requests.get")
def test_detecta_env_expuesto(mock_get, fuzzer):
    """.env accesible (200) → CRITICAL."""
    resp = MagicMock(status_code=200)
    mock_get.return_value = resp
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    env_vulns = [v for v in vulns if ".env" in v.name]
    assert len(env_vulns) >= 1
    assert env_vulns[0].severity.name == "CRITICAL"


@patch("modules.path_fuzzer.requests.get")
def test_no_reporta_404(mock_get, fuzzer):
    """Todos los paths devuelven 404 → sin alertas."""
    resp = MagicMock(status_code=404)
    mock_get.return_value = resp
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    assert len(vulns) == 0


@patch("modules.path_fuzzer.requests.get")
def test_detecta_git_expuesto(mock_get, fuzzer):
    """.git/HEAD accesible → CRITICAL."""
    resp = MagicMock(status_code=200)
    mock_get.return_value = resp
    target = Target(url="http://localhost/")
    vulns = fuzzer.run(target)
    git_vulns = [v for v in vulns if ".git" in v.name]
    assert len(git_vulns) >= 1
