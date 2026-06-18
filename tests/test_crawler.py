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


def test_normalizacion_url_agrupa_misma_estructura():
    """URLs con misma ruta y mismos params pero valores distintos deben normalizarse igual."""
    from core.crawler import normalize_url_structure
    url1 = "http://example.com/page?id=1&cat=5"
    url2 = "http://example.com/page?id=99&cat=3"
    assert normalize_url_structure(url1) == normalize_url_structure(url2)


def test_normalizacion_url_distingue_estructuras_distintas():
    """URLs con parámetros distintos deben tener estructuras diferentes."""
    from core.crawler import normalize_url_structure
    url1 = "http://example.com/page?id=1"
    url2 = "http://example.com/page?name=test"
    assert normalize_url_structure(url1) != normalize_url_structure(url2)


def test_dedup_estructural_evita_endpoints_redundantes():
    """El crawler no debe agregar endpoints con la misma estructura de URL."""
    crawler = WebCrawler("http://example.com")
    # Primera estructura: nueva
    assert crawler._is_new_structure("http://example.com/page?id=1") is True
    # Misma estructura, distinto valor: duplicada
    assert crawler._is_new_structure("http://example.com/page?id=99") is False
    # Estructura diferente: nueva
    assert crawler._is_new_structure("http://example.com/other?name=test") is True
