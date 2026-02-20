import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.file_upload_detector import FileUploadDetector


@pytest.fixture
def detector():
    return FileUploadDetector()


def _mock_response(html, content_type="text/html"):
    resp = MagicMock()
    resp.text = html
    resp.headers = {"Content-Type": content_type}
    return resp


@patch("modules.file_upload_detector.requests.get")
def test_detecta_upload_sin_restriccion(mock_get, detector):
    """Form con input type=file SIN accept → Unrestricted File Upload."""
    html = """
    <form method="POST" action="/upload" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <input type="submit" value="Upload">
    </form>
    """
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/upload.php")
    vulns = detector.run(target)
    upload_vulns = [v for v in vulns if v.name == "Unrestricted File Upload"]
    assert len(upload_vulns) == 1
    assert upload_vulns[0].severity.name == "HIGH"


@patch("modules.file_upload_detector.requests.get")
def test_no_reporta_sin_input_file(mock_get, detector):
    """Form sin input type=file no genera alertas."""
    html = """
    <form method="POST" action="/login">
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    """
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/login.php")
    vulns = detector.run(target)
    assert len(vulns) == 0


@patch("modules.file_upload_detector.requests.get")
def test_detecta_tipos_peligrosos_en_accept(mock_get, detector):
    """Input con accept que incluye extensiones peligrosas."""
    html = """
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="doc" accept=".php,.jpg,.png">
    </form>
    """
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/upload.php")
    vulns = detector.run(target)
    danger_vulns = [v for v in vulns if v.name == "Dangerous File Types Accepted"]
    assert len(danger_vulns) == 1


@patch("modules.file_upload_detector.requests.get")
def test_accept_seguro_no_reporta(mock_get, detector):
    """Input con accept solo de imágenes → sin alertas de tipo."""
    html = """
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="photo" accept=".jpg,.png,.gif">
    </form>
    """
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/upload.php")
    vulns = detector.run(target)
    danger_vulns = [v for v in vulns if v.name == "Dangerous File Types Accepted"]
    assert len(danger_vulns) == 0


@patch("modules.file_upload_detector.requests.get")
def test_detecta_multipart_faltante(mock_get, detector):
    """Form POST con file input pero sin enctype multipart."""
    html = """
    <form method="POST" action="/upload">
        <input type="file" name="doc">
    </form>
    """
    mock_get.return_value = _mock_response(html)
    target = Target(url="http://localhost/upload.php")
    vulns = detector.run(target)
    multipart_vulns = [v for v in vulns if v.name == "File Upload Missing Multipart"]
    assert len(multipart_vulns) == 1


@patch("modules.file_upload_detector.requests.get")
def test_ignora_respuestas_no_html(mock_get, detector):
    """Respuestas no-HTML (JSON, imágenes) se ignoran."""
    mock_get.return_value = _mock_response('{"status": "ok"}', "application/json")
    target = Target(url="http://localhost/api/status")
    vulns = detector.run(target)
    assert len(vulns) == 0
