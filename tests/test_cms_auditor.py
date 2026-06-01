import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.cms_auditor import CMSAuditor


@pytest.fixture
def scanner():
    return CMSAuditor()


@patch("modules.cms_auditor.requests.get")
def test_detecta_wordpress_user_enum(mock_get, scanner):
    """WordPress con endpoint REST expuesto → User Enumeration MEDIUM."""
    resp_users = MagicMock()
    resp_users.status_code = 200
    resp_users.text = '[{"id":1,"slug":"admin","name":"admin"}]'

    resp_xmlrpc = MagicMock()
    resp_xmlrpc.status_code = 404
    resp_xmlrpc.text = "Not Found"

    mock_get.side_effect = [resp_users, resp_xmlrpc]

    target = Target(url="http://localhost", context={"cms_framework": ["WordPress"]})
    vulns = scanner.run(target)
    user_vulns = [v for v in vulns if v.name == "WordPress User Enumeration"]
    assert len(user_vulns) == 1
    assert user_vulns[0].severity.name == "MEDIUM"


@patch("modules.cms_auditor.requests.get")
def test_detecta_wordpress_xmlrpc(mock_get, scanner):
    """WordPress con XML-RPC expuesto → XML-RPC Interface Exposed LOW."""
    resp_users = MagicMock()
    resp_users.status_code = 403
    resp_users.text = "Forbidden"

    resp_xmlrpc = MagicMock()
    resp_xmlrpc.status_code = 405
    resp_xmlrpc.text = "XML-RPC server accepts POST requests only."

    mock_get.side_effect = [resp_users, resp_xmlrpc]

    target = Target(url="http://localhost", context={"cms_framework": ["WordPress"]})
    vulns = scanner.run(target)
    xmlrpc_vulns = [v for v in vulns if v.name == "XML-RPC Interface Exposed"]
    assert len(xmlrpc_vulns) == 1
    assert xmlrpc_vulns[0].severity.name == "LOW"


@patch("modules.cms_auditor.requests.get")
def test_detecta_joomla_version_disclosure(mock_get, scanner):
    """Joomla con manifiesto accesible → Joomla Version Disclosure LOW."""
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<?xml version="1.0"?><extension version="3.9.0"></extension>'
    mock_get.return_value = resp

    target = Target(url="http://localhost", context={"cms_framework": ["Joomla"]})
    vulns = scanner.run(target)
    joomla_vulns = [v for v in vulns if v.name == "Joomla Version Disclosure"]
    assert len(joomla_vulns) == 1
    assert joomla_vulns[0].severity.name == "LOW"


@patch("modules.cms_auditor.requests.get")
def test_sin_cms_no_reporta_nada(mock_get, scanner):
    """Sin CMS en contexto → sin hallazgos y sin requests."""
    target = Target(url="http://localhost", context={"cms_framework": []})
    vulns = scanner.run(target)
    assert len(vulns) == 0
    mock_get.assert_not_called()
