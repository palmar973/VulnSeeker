import logging
import re
import requests
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.CVE")

# Base de datos local de versiones EOL / con CVEs conocidos críticos
# Formato: (tech_regex, version_max_vulnerable, CVE, descripción)
KNOWN_VULNS = [
    # Apache
    ("apache", "2.4.49", "CVE-2021-41773", "Path Traversal & RCE", Severity.CRITICAL),
    ("apache", "2.4.50", "CVE-2021-42013", "Path Traversal bypass de fix anterior", Severity.CRITICAL),
    ("apache", "2.4.48", "CVE-2021-40438", "SSRF via mod_proxy", Severity.HIGH),

    # Nginx
    ("nginx", "1.16.1", "CVE-2019-20372", "HTTP Request Smuggling", Severity.HIGH),

    # PHP
    ("php", "7.4.33", "EOL", "PHP 7.4 llegó a End-of-Life (Nov 2022), sin parches de seguridad", Severity.HIGH),
    ("php", "7.3.33", "EOL", "PHP 7.3 llegó a End-of-Life (Dic 2021)", Severity.HIGH),
    ("php", "5.6.40", "EOL+CVEs", "PHP 5.x tiene múltiples CVEs críticos y no recibe parches", Severity.CRITICAL),
    ("php", "8.0.30", "EOL", "PHP 8.0 llegó a End-of-Life (Nov 2023)", Severity.MEDIUM),
    ("php", "8.1.27", "CVE-2024-2756", "Cookie bypass en PHP 8.1", Severity.HIGH),

    # IIS
    ("iis", "7.5", "CVE-2017-7269", "Buffer overflow en WebDAV (RCE)", Severity.CRITICAL),
    ("iis", "6.0", "CVE-2017-7269", "Buffer overflow en WebDAV (RCE)", Severity.CRITICAL),

    # OpenSSL (a veces aparece en headers)
    ("openssl", "1.0.1", "CVE-2014-0160", "Heartbleed - fuga masiva de memoria", Severity.CRITICAL),
    ("openssl", "1.0.2", "CVE-2016-2107", "Padding Oracle en AES-NI CBC", Severity.HIGH),

    # jQuery (detectable en HTML)
    ("jquery", "1.12.4", "CVE-2020-11022", "XSS via HTML injection en jQuery < 3.5.0", Severity.MEDIUM),
    ("jquery", "2.2.4", "CVE-2020-11022", "XSS via HTML injection en jQuery < 3.5.0", Severity.MEDIUM),
    ("jquery", "3.4.1", "CVE-2020-11022", "XSS via HTML injection en jQuery < 3.5.0", Severity.MEDIUM),
]


class CVELookupScanner(ScannerModule):
    """Cruza tecnologías detectadas con CVEs conocidos (OWASP A06)."""

    @property
    def name(self) -> str:
        return "CVE Lookup Scanner"

    @property
    def description(self) -> str:
        return "Identifica versiones de software con vulnerabilidades conocidas (CVE/EOL)."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            response = requests.head(
                target.url, headers=headers, timeout=5, verify=False
            )

            # Extraer versiones de los headers
            server = response.headers.get("Server", "")
            powered = response.headers.get("X-Powered-By", "")
            full_banner = f"{server} {powered}".lower()

            if server:
                logger.info(f"🔍 CVE Scanner: Server={server}, Powered={powered}")

            # Check 1: Comparar con base de datos local de CVEs conocidos
            self._check_local_db(full_banner, target.url, vulns)

            # Check 2: Buscar jQuery vulnerable en el HTML
            self._check_jquery(target, vulns)

            # Check 3: Server banner demasiado verbose
            if server and re.search(r'\d+\.\d+', server):
                vulns.append(Vulnerability(
                    name="Server Version Disclosure",
                    description=(
                        f"El servidor expone su versión en el header: '{server}'. "
                        f"Esto facilita a atacantes buscar exploits específicos."
                    ),
                    severity=Severity.LOW,
                    target_url=target.url,
                    payload=f"Server: {server}"
                ))

            # Check 4: X-Powered-By presente (information disclosure)
            if powered:
                vulns.append(Vulnerability(
                    name="X-Powered-By Disclosure",
                    description=(
                        f"El header 'X-Powered-By: {powered}' revela la tecnología "
                        f"del backend. Esto ayuda a atacantes a planificar ataques dirigidos."
                    ),
                    severity=Severity.LOW,
                    target_url=target.url,
                    payload=f"X-Powered-By: {powered}"
                ))

        except requests.RequestException as e:
            logger.debug(f"Error de conexión CVE: {e}")
        except Exception as e:
            logger.error(f"Error en CVELookupScanner: {e}")

        return vulns

    def _check_local_db(self, banner, url, vulns):
        """Compara el banner del servidor contra CVEs conocidos."""
        for tech, version, cve, desc, severity in KNOWN_VULNS:
            # Buscar la tecnología y extraer su versión del banner
            pattern = rf'{tech}[/\s]*(\d+\.\d+[\.\d]*)'
            match = re.search(pattern, banner)

            if match:
                detected_version = match.group(1)

                # Comparar versiones: si la detectada es <= la vulnerable
                if self._version_lte(detected_version, version):
                    vulns.append(Vulnerability(
                        name=f"Known Vulnerability: {cve}",
                        description=(
                            f"{tech.capitalize()} {detected_version} es vulnerable. "
                            f"{desc}."
                        ),
                        severity=severity,
                        target_url=url,
                        payload=f"{tech}/{detected_version} → {cve}"
                    ))

    def _check_jquery(self, target, vulns):
        """Busca versiones de jQuery vulnerables en el HTML."""
        try:
            headers = target.headers or {"User-Agent": "VulnSeeker/1.0"}
            resp = requests.get(target.url, headers=headers, timeout=5, verify=False)

            # Buscar patrones como "jquery-3.4.1.min.js" o "jQuery v1.12.4"
            jquery_patterns = [
                r'jquery[.-]?(\d+\.\d+\.\d+)',
                r'jQuery v(\d+\.\d+\.\d+)',
                r'jquery\.min\.js\?ver=(\d+\.\d+\.\d+)',
            ]

            for pattern in jquery_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if self._version_lte(version, "3.4.1"):
                        vulns.append(Vulnerability(
                            name="Vulnerable jQuery Version",
                            description=(
                                f"jQuery {version} detectada. Versiones < 3.5.0 son "
                                f"vulnerables a XSS (CVE-2020-11022, CVE-2020-11023)."
                            ),
                            severity=Severity.MEDIUM,
                            target_url=target.url,
                            payload=f"jQuery {version} → CVE-2020-11022"
                        ))
                    break

        except requests.RequestException:
            pass

    @staticmethod
    def _version_lte(detected: str, known: str) -> bool:
        """Compara dos versiones. Retorna True si detected <= known."""
        try:
            d_parts = [int(x) for x in detected.split(".")]
            k_parts = [int(x) for x in known.split(".")]

            # Igualar longitud con ceros
            while len(d_parts) < len(k_parts):
                d_parts.append(0)
            while len(k_parts) < len(d_parts):
                k_parts.append(0)

            return d_parts <= k_parts
        except (ValueError, AttributeError):
            return False
