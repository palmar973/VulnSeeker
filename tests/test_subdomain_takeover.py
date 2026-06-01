import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.subdomain_takeover import SubdomainTakeover


@pytest.fixture
def scanner():
    return SubdomainTakeover()


@patch("modules.subdomain_takeover.requests.get")
@patch("modules.subdomain_takeover.dns.resolver.resolve")
def test_detecta_takeover_github_pages(mock_resolve, mock_get, scanner):
    """CNAME a github.io con error page → Subdomain Takeover HIGH."""
    cname_record = MagicMock()
    cname_record.target = "user.github.io."
    mock_resolve.return_value = [cname_record]

    resp = MagicMock()
    resp.text = "There isn't a GitHub Pages site here."
    mock_get.return_value = resp

    target = Target(url="http://sub.example.com")
    vulns = scanner.run(target)
    takeover_vulns = [v for v in vulns if "Subdomain Takeover" in v.name]
    assert len(takeover_vulns) == 1
    assert takeover_vulns[0].severity.name == "HIGH"
    assert "GitHub Pages" in takeover_vulns[0].name


@patch("modules.subdomain_takeover.requests.get")
@patch("modules.subdomain_takeover.dns.resolver.resolve")
def test_no_takeover_contenido_normal(mock_resolve, mock_get, scanner):
    """CNAME a github.io pero con contenido normal → sin takeover."""
    cname_record = MagicMock()
    cname_record.target = "user.github.io."
    mock_resolve.return_value = [cname_record]

    resp = MagicMock()
    resp.text = "<html><body>Welcome to my site</body></html>"
    mock_get.return_value = resp

    target = Target(url="http://sub.example.com")
    vulns = scanner.run(target)
    takeover_vulns = [v for v in vulns if "Subdomain Takeover" in v.name]
    assert len(takeover_vulns) == 0


@patch("modules.subdomain_takeover.dns.resolver.resolve")
def test_cname_sin_coincidencia_no_reporta(mock_resolve, scanner):
    """CNAME a servicio no listado → sin hallazgos."""
    cname_record = MagicMock()
    cname_record.target = "cdn.someother.com."
    mock_resolve.return_value = [cname_record]

    target = Target(url="http://sub.example.com")
    vulns = scanner.run(target)
    assert len(vulns) == 0


@patch("modules.subdomain_takeover.dns.resolver.resolve")
def test_dns_nxdomain_no_crashea(mock_resolve, scanner):
    """NXDOMAIN en DNS → sin hallazgos ni crash."""
    import dns.resolver
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()

    target = Target(url="http://noexiste.example.com")
    vulns = scanner.run(target)
    assert len(vulns) == 0
