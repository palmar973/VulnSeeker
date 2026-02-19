"""
Tests unitarios: Crawler (core/crawler.py).
Valida el filtrado de URLs fuera de scope.
"""
from core.crawler import WebCrawler


def test_url_en_scope_es_aceptada():
    """URLs del mismo dominio deben pasar el filtro de scope."""
    crawler = WebCrawler("http://example.com")
    assert crawler._is_in_scope("http://example.com/pagina") is True
    assert crawler._is_in_scope("http://example.com/admin/login") is True


def test_url_fuera_de_scope_es_rechazada():
    """URLs de dominios externos deben ser rechazadas."""
    crawler = WebCrawler("http://example.com")
    assert crawler._is_in_scope("http://evil.com/hack") is False
    assert crawler._is_in_scope("http://sub.example.com/page") is False


def test_url_con_esquema_invalido_es_rechazada():
    """Solo http y https deben ser aceptados."""
    crawler = WebCrawler("http://example.com")
    assert crawler._is_in_scope("ftp://example.com/file") is False
    assert crawler._is_in_scope("javascript:alert(1)") is False


def test_base_domain_se_extrae_correctamente():
    """El dominio base se debe extraer de la URL de inicio."""
    crawler = WebCrawler("http://testphp.vulnweb.com/login.php")
    assert crawler.base_domain == "testphp.vulnweb.com"
