"""
Tests unitarios: Fingerprinter (core/fingerprinter.py).
Valida la detección de tecnologías a partir de headers HTTP simulados.
"""
from unittest.mock import patch, MagicMock
from core.fingerprinter import TechFingerprinter


def test_detecta_nginx_en_header_server():
    """Debe detectar Nginx cuando el header Server lo indica."""
    fp = TechFingerprinter()
    result = fp._analyze_headers({'server': 'nginx/1.21.0', 'x-powered-by': ''})
    assert 'Nginx' in result['server']


def test_detecta_apache_en_header_server():
    """Debe detectar Apache cuando el header Server lo indica."""
    fp = TechFingerprinter()
    result = fp._analyze_headers({'server': 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': ''})
    assert 'Apache' in result['server']


def test_detecta_php_en_powered_by():
    """Debe detectar PHP en el header X-Powered-By."""
    fp = TechFingerprinter()
    result = fp._analyze_headers({'server': '', 'x-powered-by': 'PHP/7.4.3'})
    assert 'Php' in result['powered_by']


def test_detecta_wordpress_en_html():
    """Debe detectar WordPress por marcadores en el HTML."""
    fp = TechFingerprinter()
    html = '<html><body><link href="/wp-content/themes/style.css"></body></html>'
    result = fp._analyze_html(html.lower())
    assert 'Wordpress' in result


def test_no_detecta_nada_en_headers_vacios():
    """Headers vacíos no deben producir detecciones falsas."""
    fp = TechFingerprinter()
    result = fp._analyze_headers({'server': '', 'x-powered-by': ''})
    assert result['server'] == []
    assert result['powered_by'] == []


def test_analyze_completo_con_mock():
    """El método analyze() completo debe funcionar con respuestas simuladas."""
    fp = TechFingerprinter()

    fake_headers = {'server': 'nginx/1.21.0', 'x-powered-by': 'PHP/8.1'}
    fake_html = '<html><body><link href="/wp-content/themes/style.css"></body></html>'

    with patch.object(fp, '_get_headers', return_value=fake_headers), \
         patch.object(fp, '_get_html', return_value=fake_html.lower()):
        result = fp.analyze("http://test.com")

    assert result['confidence'] == 'HIGH'
    assert 'Nginx' in result['server']
    assert 'Php' in result['powered_by']
    assert 'Wordpress' in result['cms_framework']


def test_analyze_paths_ignora_catch_all():
    """Anti-FP: si una ruta aleatoria inexistente devuelve 200 (catch-all/SPA), no se
    debe inferir CMS por path (era el origen del falso 'Joomla/WordPress' en Juice Shop)."""
    fp = TechFingerprinter()
    with patch("core.fingerprinter.requests.head", return_value=MagicMock(status_code=200)):
        assert fp._analyze_paths("http://spa.local/") == []


def test_analyze_paths_detecta_con_404_real():
    """Con 404 real en la sonda, sí se infiere CMS por rutas conocidas (sin regresión)."""
    fp = TechFingerprinter()

    def _head(url, *args, **kwargs):
        if url.endswith("/wp-admin/") or url.endswith("/administrator/") or url.endswith("/sites/"):
            return MagicMock(status_code=200)
        return MagicMock(status_code=404)

    with patch("core.fingerprinter.requests.head", side_effect=_head):
        detected = fp._analyze_paths("http://classic.local/")

    assert "WordPress" in detected
    assert "Joomla" in detected
