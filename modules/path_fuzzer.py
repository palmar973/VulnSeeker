#!/usr/bin/env python3.14
"""
PathFuzzer - FASE 13: Cazador de archivos y directorios sensibles expuestos.
Descubre .env, .git, backups SQL, paneles admin ocultos, etc.
"""

import requests
from typing import List
from core.models import ScannerModule, Target, Vulnerability, Severity
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from urllib.parse import urljoin


class PathFuzzer(ScannerModule):
    """Descubridor activo de paths sensibles expuestos."""

    CRITICAL_PATHS = {
        # Secretos absolutos
        ".env": Severity.CRITICAL,
        ".env.bak": Severity.CRITICAL,
        ".env.production": Severity.CRITICAL,
        ".git/HEAD": Severity.CRITICAL,
        ".git/config": Severity.CRITICAL,
        ".svn/entries": Severity.CRITICAL,
        "backup.sql": Severity.CRITICAL,
        "database.sql": Severity.CRITICAL,
        "dump.sql": Severity.CRITICAL,
        "users.sql": Severity.CRITICAL,
        "config.php.bak": Severity.CRITICAL,
        "wp-config.php.bak": Severity.CRITICAL,

        # Configs sensibles y paneles admin
        "web.config": Severity.HIGH,
        "Dockerfile": Severity.HIGH,
        "admin/": Severity.HIGH,
        "administrator/": Severity.HIGH,
        "phpinfo.php": Severity.HIGH,
        "test.php": Severity.HIGH,
        "debug.php": Severity.HIGH,
        "config.json": Severity.HIGH,
        ".DS_Store": Severity.HIGH,

        # Menos críticos pero interesantes
        "robots.txt": Severity.INFO,
        "sitemap.xml": Severity.INFO,
    }

    @property
    def name(self) -> str:
        return "Path Fuzzer"

    @property
    def description(self) -> str:
        return "Descubre archivos sensibles (.env, .git, backups, admin panels)"

    def _check_path(self, base_url: str, path: str, timeout: float = 2.5) -> tuple[bool, str]:
        """Verifica un path individual con timeout agresivo."""
        try:
            test_url = urljoin(base_url, path)
            response = requests.get(
                test_url,
                timeout=timeout,
                allow_redirects=False,  # No seguir redirecciones
                verify=False
            )
            return response.status_code == 200, test_url
        except:
            return False, ""

    def run(self, target: Target) -> List[Vulnerability]:
        """Ejecuta fuzzing paralelo de paths críticos."""
        vulnerabilities: List[Vulnerability] = []
        base_url = str(target.url)

        logger = None  # Evita dependencias circulares

        def log_if_debug(msg: str):
            # Logging silencioso para no romper el engine
            pass

        log_if_debug(f"🕵️‍♂️ Fuzzing {len(self.CRITICAL_PATHS)} paths críticos...")

        # Fuzzing paralelo (max 8 threads por balance velocidad/estabilidad)
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Submit todos los paths
            future_to_path = {
                executor.submit(self._check_path, base_url, path): path
                for path in self.CRITICAL_PATHS.keys()
            }

            # Procesar resultados completados
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    is_exposed, full_url = future.result()

                    if is_exposed:
                        severity = self.CRITICAL_PATHS[path]
                        vuln_name = f"EXPOSED: {path}"

                        vulnerabilities.append(Vulnerability(
                            name=vuln_name,
                            description=f"Archivo/directorio sensible '{path}' accesible públicamente",
                            severity=severity,
                            target_url=full_url,
                            payload=f"¡ELIMINAR inmediatamente! {path} expuesto → Riesgo CRÍTICO"
                        ))

                        log_if_debug(f"✅ CRÍTICO: {path} → {full_url}")

                except Exception:
                    pass

        log_if_debug(f"🎯 PathFuzzer completado: {len(vulnerabilities)} secretos encontrados")
        return vulnerabilities