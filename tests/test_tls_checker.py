"""Tests para el módulo SSL/TLS Checker."""

from unittest.mock import patch, MagicMock
from modules.tls_checker import TLSChecker
from core.models import Target, Severity


def test_detecta_http_sin_cifrado():
    """Un sitio HTTP debe generar vulnerabilidad por falta de HTTPS."""
    checker = TLSChecker()
    target = Target(url="http://insecure-site.com")

    with patch.object(checker, '_get_certificate', return_value=None), \
         patch.object(checker, '_check_weak_protocols', return_value=[]):
        vulns = checker.run(target)

    assert len(vulns) == 1
    assert vulns[0].name == "No HTTPS"
    assert vulns[0].severity == Severity.HIGH


def test_no_reporta_https_valido():
    """Un sitio HTTPS con certificado válido no debe generar alerta de HTTP."""
    checker = TLSChecker()
    target = Target(url="https://secure-site.com")

    with patch.object(checker, '_get_certificate', return_value=None), \
         patch.object(checker, '_check_weak_protocols', return_value=[]):
        vulns = checker.run(target)

    # No debe haber vuln de "No HTTPS"
    assert not any(v.name == "No HTTPS" for v in vulns)


def test_detecta_certificado_expirado():
    """Un certificado expirado debe generar vulnerabilidad."""
    checker = TLSChecker()
    fake_cert = {"notAfter": "Jan 01 00:00:00 2020 GMT"}

    vulns = checker._check_certificate(fake_cert, "expired.com", "https://expired.com")

    assert len(vulns) == 1
    assert vulns[0].name == "Expired SSL Certificate"
    assert vulns[0].severity == Severity.HIGH


def test_detecta_certificado_por_expirar():
    """Un certificado que expira en menos de 30 días debe generar alerta."""
    from datetime import datetime, timedelta, timezone
    checker = TLSChecker()

    # Certificado que expira en 15 días
    future = datetime.now(timezone.utc) + timedelta(days=15)
    date_str = future.strftime("%b %d %H:%M:%S %Y GMT")
    fake_cert = {"notAfter": date_str}

    vulns = checker._check_certificate(fake_cert, "expiring.com", "https://expiring.com")

    assert len(vulns) == 1
    assert vulns[0].name == "SSL Certificate Expiring Soon"
    assert vulns[0].severity == Severity.LOW


def test_funciona_sin_url_valida():
    """No debe fallar con una URL sin hostname."""
    checker = TLSChecker()
    target = Target(url="not-a-url")

    vulns = checker.run(target)
    assert isinstance(vulns, list)
