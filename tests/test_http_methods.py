import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.http_method_scanner import HTTPMethodTamperingScanner


@pytest.fixture
def scanner():
    return HTTPMethodTamperingScanner()


def _mock_options_response(allow=""):
    resp = MagicMock()
    resp.headers = {"Allow": allow} if allow else {}
    return resp


@patch("modules.http_method_scanner.requests.request")
@patch("modules.http_method_scanner.requests.options")
def test_detecta_put_en_options(mock_options, mock_request, scanner):
    """OPTIONS anuncia PUT → Dangerous HTTP Method: PUT (HIGH)."""
    mock_options.return_value = _mock_options_response("GET, POST, PUT, OPTIONS")
    mock_request.return_value = MagicMock(status_code=405, text="Not Allowed")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    put_vulns = [v for v in vulns if "PUT" in v.name]
    assert len(put_vulns) == 1
    assert put_vulns[0].severity.name == "HIGH"


@patch("modules.http_method_scanner.requests.request")
@patch("modules.http_method_scanner.requests.options")
def test_detecta_delete_en_options(mock_options, mock_request, scanner):
    """OPTIONS anuncia DELETE → Dangerous HTTP Method: DELETE (HIGH)."""
    mock_options.return_value = _mock_options_response("GET, DELETE")
    mock_request.return_value = MagicMock(status_code=405, text="Not Allowed")
    target = Target(url="http://localhost/api")
    vulns = scanner.run(target)
    del_vulns = [v for v in vulns if "DELETE" in v.name]
    assert len(del_vulns) == 1


@patch("modules.http_method_scanner.requests.request")
@patch("modules.http_method_scanner.requests.options")
def test_detecta_trace_activo(mock_options, mock_request, scanner):
    """TRACE responde 200 con reflejo → XST vulnerable."""
    mock_options.return_value = _mock_options_response("GET, POST")
    mock_request.return_value = MagicMock(status_code=200, text="TRACE / HTTP/1.1")
    target = Target(url="http://localhost/")
    vulns = scanner.run(target)
    trace_vulns = [v for v in vulns if "TRACE" in v.name]
    assert len(trace_vulns) == 1


@patch("modules.http_method_scanner.requests.request")
@patch("modules.http_method_scanner.requests.options")
def test_no_reporta_metodos_seguros(mock_options, mock_request, scanner):
    """Solo GET, POST, HEAD, OPTIONS → sin alertas."""
    mock_options.return_value = _mock_options_response("GET, POST, HEAD, OPTIONS")
    mock_request.return_value = MagicMock(status_code=405, text="Not Allowed")
    target = Target(url="http://localhost/page")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.http_method_scanner.requests.request")
@patch("modules.http_method_scanner.requests.options")
def test_sin_allow_header_no_reporta(mock_options, mock_request, scanner):
    """Sin header Allow en OPTIONS → sin alertas de OPTIONS."""
    mock_options.return_value = _mock_options_response("")
    mock_request.return_value = MagicMock(status_code=405, text="")
    target = Target(url="http://localhost/page")
    vulns = scanner.run(target)
    assert len(vulns) == 0
