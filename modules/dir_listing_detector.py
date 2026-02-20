import logging
import requests
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.DirListing")

# Indicadores de directory listing en HTML
LISTING_SIGNATURES = [
    "Index of /",
    "Directory listing for",
    "<title>Directory listing",
    "Parent Directory",
    "[To Parent Directory]",
    "directory listing denied",
]

# Paths comunes donde suele haber directory listing
COMMON_DIRS = [
    "/images/", "/uploads/", "/files/", "/static/",
    "/assets/", "/backup/", "/tmp/", "/logs/",
    "/includes/", "/css/", "/js/", "/media/",
]


class DirectoryListingDetector(ScannerModule):
    """Detecta directory listing expuesto en el servidor (OWASP A05)."""

    @property
    def name(self) -> str:
        return "Directory Listing Detector"

    @property
    def description(self) -> str:
        return "Identifica directorios del servidor con listado de archivos habilitado."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}

            # Check 1: La URL actual tiene directory listing
            self._check_url(target.url, headers, vulns)

            # Check 2: Probar directorios comunes
            from urllib.parse import urlparse
            parsed = urlparse(target.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for dir_path in COMMON_DIRS:
                test_url = base_url + dir_path
                self._check_url(test_url, headers, vulns)

        except Exception as e:
            logger.error(f"Error en DirectoryListingDetector: {e}")

        return vulns

    def _check_url(self, url, headers, vulns):
        """Verifica si una URL muestra directory listing."""
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)

            if response.status_code != 200:
                return

            text = response.text
            for signature in LISTING_SIGNATURES:
                if signature.lower() in text.lower():
                    vulns.append(Vulnerability(
                        name="Directory Listing Enabled",
                        description=(
                            f"El directorio '{url}' expone su listado de archivos. "
                            f"Un atacante puede ver la estructura interna del servidor, "
                            f"descubrir archivos sensibles y planificar ataques dirigidos."
                        ),
                        severity=Severity.MEDIUM,
                        target_url=url,
                        payload=f"GET {url} → {signature}"
                    ))
                    break  # Una firma basta por URL

        except requests.RequestException:
            pass
