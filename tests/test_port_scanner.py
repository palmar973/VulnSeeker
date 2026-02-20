import pytest
from unittest.mock import patch, MagicMock
from core.models import Target
from modules.port_scanner import PortScanner


@pytest.fixture
def scanner():
    return PortScanner()


@patch("modules.port_scanner.socket.socket")
def test_detecta_puerto_abierto_critico(mock_socket_cls, scanner):
    """Puerto 21 (FTP) abierto → alerta HIGH."""
    sock_instance = MagicMock()
    # connect_ex retorna 0 = abierto para todos los puertos
    sock_instance.connect_ex.return_value = 0
    mock_socket_cls.return_value = sock_instance

    target = Target(url="http://localhost/")
    vulns = scanner.run(target)
    # Debería detectar ports con severidad (21, 22, 23, 3306, 8080)
    # No reporta 80/443 porque tienen None como severidad
    assert len(vulns) >= 1
    ftp_vulns = [v for v in vulns if "21" in v.name and "FTP" in v.name]
    assert len(ftp_vulns) == 1


@patch("modules.port_scanner.socket.socket")
def test_no_reporta_puertos_cerrados(mock_socket_cls, scanner):
    """Todos los puertos cerrados → sin alertas."""
    sock_instance = MagicMock()
    sock_instance.connect_ex.return_value = 1  # 1 = cerrado
    mock_socket_cls.return_value = sock_instance

    target = Target(url="http://localhost/")
    vulns = scanner.run(target)
    assert len(vulns) == 0
