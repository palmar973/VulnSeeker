import logging
from typing import List
import requests
from core.scanner_types import ScannerModule, Target, Vulnerability
from core.models import Severity

logger = logging.getLogger("VulnSeeker")


class ExposureScanner(ScannerModule):
    @property
    def name(self) -> str:
        return "Exposure Scanner"

    @property
    def description(self) -> str:
        return "Detecta archivos de configuración y backups expuestos públicamente."

    def run(self, target: Target) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        base = target.url.rstrip("/")
        critical_files = [
            ".env",
            ".git/HEAD",
            ".git/config",
            ".gitlab-ci.yml",
            "docker-compose.yml",
            "config.php.bak",
            "wp-config.php.bak",
            "composer.json",
            "package.json",
            "id_rsa",
            "id_rsa.pub",
            "backup.sql",
            "database.sql",
            "dump.sql",
            ".DS_Store",
        ]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        for path in critical_files:
            url = f"{base}/{path}"
            try:
                logger.info(f"🔍 Exposure Scanner: Verificando {url}...")
                resp = requests.get(url, headers=headers, timeout=5)
                if resp.status_code != 200:
                    continue
                content = resp.text or ""
                if not content.strip():
                    continue
                # Filtro anti falsos positivos: si no buscamos HTML pero la respuesta es HTML, saltar
                lowered = content.lower()
                if "<!doctype html" in lowered or "<html" in lowered:
                    # Evitar error 200 con página de error
                    continue

                sev = Severity.MEDIUM
                if path.startswith(".env") or path.startswith(".git") or path.endswith(".sql"):
                    sev = Severity.HIGH

                findings.append(
                    Vulnerability(
                        name=f"Archivo sensible expuesto ({path})",
                        description=f"El recurso {path} es accesible públicamente.",
                        severity=sev,
                        target_url=url,
                        evidence=f"HTTP 200 - {len(content)} bytes",
                    )
                )
            except Exception as e:
                logger.error(f"❌ Error en ExposureScanner para {url}: {e}")
        return findings
