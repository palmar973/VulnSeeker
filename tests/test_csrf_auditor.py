"""Tests para el módulo CSRF Auditor."""

from modules.csrf_auditor import CSRFAuditor
from core.models import Target, PageElement, Severity


def test_detecta_formulario_post_sin_token_csrf():
    """Un formulario POST sin token anti-CSRF debe generar vulnerabilidad."""
    auditor = CSRFAuditor()
    form = PageElement(
        url="http://test.com/login",
        method="POST",
        params={"username": "admin", "password": "123"},
        is_form=True
    )
    target = Target(url="http://test.com/login", elements=[form])

    vulns = auditor.run(target)

    assert len(vulns) == 1
    assert vulns[0].name == "Missing CSRF Token"
    assert vulns[0].severity == Severity.MEDIUM
    assert "username" in vulns[0].description


def test_no_reporta_si_tiene_csrf_token():
    """Un formulario POST con token anti-CSRF no debe generar vulnerabilidad."""
    auditor = CSRFAuditor()
    form = PageElement(
        url="http://test.com/transfer",
        method="POST",
        params={"amount": "100", "csrf_token": "abc123"},
        is_form=True
    )
    target = Target(url="http://test.com/transfer", elements=[form])

    vulns = auditor.run(target)

    assert len(vulns) == 0


def test_ignora_formularios_get():
    """Los formularios GET no deben ser evaluados."""
    auditor = CSRFAuditor()
    form = PageElement(
        url="http://test.com/search",
        method="GET",
        params={"q": "hello"},
        is_form=True
    )
    target = Target(url="http://test.com/search", elements=[form])

    vulns = auditor.run(target)

    assert len(vulns) == 0


def test_detecta_token_por_substring():
    """Debe reconocer variantes como 'authenticity_token' o '__RequestVerificationToken'."""
    auditor = CSRFAuditor()
    form = PageElement(
        url="http://test.com/settings",
        method="POST",
        params={"name": "test", "authenticity_token": "xyz"},
        is_form=True
    )
    target = Target(url="http://test.com/settings", elements=[form])

    vulns = auditor.run(target)

    assert len(vulns) == 0


def test_funciona_sin_elements():
    """No debe fallar si el target no tiene elementos."""
    auditor = CSRFAuditor()
    target = Target(url="http://test.com/about")

    vulns = auditor.run(target)

    assert len(vulns) == 0
