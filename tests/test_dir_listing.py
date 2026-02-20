import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.dir_listing_detector import DirectoryListingDetector


@pytest.fixture
def detector():
    return DirectoryListingDetector()


@patch("modules.dir_listing_detector.requests.get")
def test_detecta_index_of(mock_get, detector):
    """Respuesta con 'Index of /' → Directory Listing Enabled."""
    resp = MagicMock(status_code=200, text="<html><title>Index of /uploads</title></html>")
    resp.headers = {}
    mock_get.return_value = resp
    target = Target(url="http://localhost/uploads/")
    vulns = detector.run(target)
    dir_vulns = [v for v in vulns if v.name == "Directory Listing Enabled"]
    assert len(dir_vulns) >= 1


@patch("modules.dir_listing_detector.requests.get")
def test_detecta_parent_directory(mock_get, detector):
    """Respuesta con 'Parent Directory' → listing detectado."""
    resp = MagicMock(status_code=200, text="<a href='../'>Parent Directory</a>")
    resp.headers = {}
    mock_get.return_value = resp
    target = Target(url="http://localhost/files/")
    vulns = detector.run(target)
    dir_vulns = [v for v in vulns if v.name == "Directory Listing Enabled"]
    assert len(dir_vulns) >= 1


@patch("modules.dir_listing_detector.requests.get")
def test_no_reporta_pagina_normal(mock_get, detector):
    """Página HTML normal sin listing → sin alertas."""
    resp = MagicMock(status_code=200, text="<html><body>Bienvenido</body></html>")
    resp.headers = {}
    mock_get.return_value = resp
    target = Target(url="http://localhost/")
    vulns = detector.run(target)
    dir_vulns = [v for v in vulns if v.name == "Directory Listing Enabled"]
    assert len(dir_vulns) == 0


@patch("modules.dir_listing_detector.requests.get")
def test_ignora_404(mock_get, detector):
    """Directorios que dan 404 se ignoran."""
    resp = MagicMock(status_code=404, text="Not Found")
    resp.headers = {}
    mock_get.return_value = resp
    target = Target(url="http://localhost/nonexistent/")
    vulns = detector.run(target)
    assert len(vulns) == 0
