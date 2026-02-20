import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.cve_lookup import CVELookupScanner


@pytest.fixture
def scanner():
    return CVELookupScanner()


def _mock_head(server="", powered=""):
    resp = MagicMock()
    headers = {}
    if server:
        headers["Server"] = server
    if powered:
        headers["X-Powered-By"] = powered
    resp.headers = headers
    return resp


@patch("modules.cve_lookup.requests.get")
@patch("modules.cve_lookup.requests.head")
def test_detecta_apache_vulnerable(mock_head, mock_get, scanner):
    """Apache 2.4.49 → CVE-2021-41773 (CRITICAL)."""
    mock_head.return_value = _mock_head(server="Apache/2.4.49")
    mock_get.return_value = MagicMock(text="<html>normal</html>")
    target = Target(url="http://test.com/")
    vulns = scanner.run(target)
    cve_vulns = [v for v in vulns if "CVE-2021-41773" in v.name]
    assert len(cve_vulns) >= 1
    assert cve_vulns[0].severity.name == "CRITICAL"


@patch("modules.cve_lookup.requests.get")
@patch("modules.cve_lookup.requests.head")
def test_detecta_php_eol(mock_head, mock_get, scanner):
    """PHP 7.4 → End of Life (HIGH)."""
    mock_head.return_value = _mock_head(powered="PHP/7.4.33")
    mock_get.return_value = MagicMock(text="<html>normal</html>")
    target = Target(url="http://test.com/")
    vulns = scanner.run(target)
    eol_vulns = [v for v in vulns if "EOL" in v.name]
    assert len(eol_vulns) >= 1


@patch("modules.cve_lookup.requests.get")
@patch("modules.cve_lookup.requests.head")
def test_detecta_version_disclosure(mock_head, mock_get, scanner):
    """Server header con versión → Server Version Disclosure."""
    mock_head.return_value = _mock_head(server="nginx/1.21.3")
    mock_get.return_value = MagicMock(text="<html>normal</html>")
    target = Target(url="http://test.com/")
    vulns = scanner.run(target)
    disc_vulns = [v for v in vulns if v.name == "Server Version Disclosure"]
    assert len(disc_vulns) == 1


@patch("modules.cve_lookup.requests.get")
@patch("modules.cve_lookup.requests.head")
def test_detecta_powered_by_disclosure(mock_head, mock_get, scanner):
    """X-Powered-By presente → información expuesta."""
    mock_head.return_value = _mock_head(powered="Express")
    mock_get.return_value = MagicMock(text="<html>normal</html>")
    target = Target(url="http://test.com/")
    vulns = scanner.run(target)
    xpb_vulns = [v for v in vulns if v.name == "X-Powered-By Disclosure"]
    assert len(xpb_vulns) == 1


@patch("modules.cve_lookup.requests.get")
@patch("modules.cve_lookup.requests.head")
def test_detecta_jquery_vulnerable(mock_head, mock_get, scanner):
    """jQuery 1.12.4 en HTML → CVE-2020-11022."""
    mock_head.return_value = _mock_head()
    mock_get.return_value = MagicMock(
        text='<script src="/js/jquery-1.12.4.min.js"></script>'
    )
    target = Target(url="http://test.com/")
    vulns = scanner.run(target)
    jq_vulns = [v for v in vulns if v.name == "Vulnerable jQuery Version"]
    assert len(jq_vulns) == 1


@patch("modules.cve_lookup.requests.get")
@patch("modules.cve_lookup.requests.head")
def test_no_reporta_versiones_seguras(mock_head, mock_get, scanner):
    """Apache moderno sin versión vulnerable → sin CVE alerts."""
    mock_head.return_value = _mock_head(server="Apache/2.4.58")
    mock_get.return_value = MagicMock(text="<html>normal</html>")
    target = Target(url="http://test.com/")
    vulns = scanner.run(target)
    cve_vulns = [v for v in vulns if "CVE-" in v.name]
    assert len(cve_vulns) == 0


def test_version_comparison(scanner):
    """Verificar lógica de comparación de versiones."""
    assert scanner._version_lte("2.4.49", "2.4.49") is True  # igual
    assert scanner._version_lte("2.4.48", "2.4.49") is True  # menor
    assert scanner._version_lte("2.4.50", "2.4.49") is False  # mayor
    assert scanner._version_lte("1.0", "2.0") is True
    assert scanner._version_lte("3.0", "2.0") is False


@patch("modules.cve_lookup.requests.get")
def test_nvd_api_devuelve_cves(mock_get, scanner):
    """NVD API retorna CVEs → se agregan como vulnerabilidades NVD."""
    nvd_response = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2023-99999",
                "descriptions": [
                    {"lang": "en", "value": "Critical RCE in nginx test"}
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8}
                    }]
                }
            }
        }]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = nvd_response
    mock_get.return_value = mock_resp

    vulns = []
    scanner._query_nvd("nginx/1.25.3 ", "http://test.com/", vulns)
    nvd_vulns = [v for v in vulns if "NVD:" in v.name]
    assert len(nvd_vulns) == 1
    assert "CVE-2023-99999" in nvd_vulns[0].name
    assert nvd_vulns[0].severity.name == "CRITICAL"


@patch("modules.cve_lookup.requests.get")
def test_nvd_api_sin_resultados(mock_get, scanner):
    """NVD API sin CVEs → sin alertas adicionales."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"totalResults": 0, "vulnerabilities": []}
    mock_get.return_value = mock_resp

    vulns = []
    scanner._query_nvd("nginx/99.99.99 ", "http://test.com/", vulns)
    assert len(vulns) == 0
