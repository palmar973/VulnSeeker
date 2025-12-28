#!/usr/bin/env python3.14
"""
PortScanner - FASE 12: Detección de puertos expuestos no estándar.
Escanea puertos críticos con timeout agresivo (0.5s).
"""

import socket
from typing import List
from core.models import Vulnerability, Severity
from core.interfaces import ScannerModule
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner(ScannerModule):
    """Escáner de puertos TCP expuestos."""

    @property
    def name(self) -> str:
        return "TCP Port Scanner"

    @property
    def description(self) -> str:
        return "Detecta puertos expuestos (FTP, SSH, Telnet, DBs, etc)"

    def run(self, target: 'Target') -> List[Vulnerability]:
        """Escaneo paralelo de puertos críticos con timeout 0.5s."""
        vulnerabilities: List[Vulnerability] = []

        # Puertos críticos a escanear
        critical_ports = {
            21: ("FTP", Severity.HIGH),  # Alta severidad
            22: ("SSH", Severity.MEDIUM),
            23: ("Telnet", Severity.HIGH),  # Muy inseguro
            80: ("HTTP", None),  # Estándar web (OK)
            443: ("HTTPS", None),  # Estándar web (OK)
            3306: ("MySQL", Severity.MEDIUM),
            8080: ("Alt HTTP", Severity.MEDIUM)
        }

        def check_port(port: int, host: str, timeout: float = 0.5) -> tuple[bool, str]:
            """Verifica si puerto está abierto."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0, critical_ports[port][0]
            except:
                return False, ""

        # Solo hostname (sin puerto) para escaneo correcto
        host = target.url.host if hasattr(target.url, 'host') else target.url

        # Escaneo paralelo (máx 4 threads para no saturar)
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_port = {
                executor.submit(check_port, port, host): port
                for port in critical_ports.keys()
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, service = future.result()

                    if is_open and critical_ports[port][1]:  # Puerto crítico ABIERTO
                        sev = critical_ports[port][1]
                        vulnerabilities.append(Vulnerability(
                            name=f"Open Port {port} ({service})",
                            description=f"Puerto {service} ({port}) expuesto públicamente",
                            severity=sev,
                            target_url=f"{host}:{port}",
                            payload=f"Recomendado: Firewall → DENY {host}:{port}"
                        ))

                except Exception:
                    # Puerto timeout/error → no vuln
                    pass

        return vulnerabilities