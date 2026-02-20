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

            # Check 5: Consultar NVD API en vivo para CVEs no cubiertos localmente
            self._query_nvd(full_banner, target.url, vulns)

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

    def _query_nvd(self, banner, url, vulns):
        """Consulta la API pública de NVD para CVEs en tiempo real."""
        # Extraer pares tecnología/versión del banner
        tech_patterns = [
            (r'apache[/\s]*(\d+\.\d+\.\d+)', 'apache'),
            (r'nginx[/\s]*(\d+\.\d+\.\d+)', 'nginx'),
            (r'php[/\s]*(\d+\.\d+\.\d+)', 'php'),
            (r'openssl[/\s]*(\d+\.\d+[\w.]*)', 'openssl'),
            (r'microsoft-iis[/\s]*(\d+\.\d+)', 'microsoft:iis'),
        ]

        for pattern, cpe_vendor in tech_patterns:
            match = re.search(pattern, banner)
            if not match:
                continue

            version = match.group(1)
            # Solo consultar NVD si la DB local no encontró nada para esta tech
            local_hits = [v for v in vulns if cpe_vendor.split(':')[-1] in v.payload.lower()]
            if local_hits:
                continue

            try:
                # NVD API 2.0 pública (sin API key, rate-limited)
                nvd_url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?keywordSearch={cpe_vendor.replace(':', '+')}+{version}"
                    f"&resultsPerPage=5"
                )
                resp = requests.get(nvd_url, timeout=10, headers={
                    "User-Agent": "VulnSeeker/1.0"
                })

                if resp.status_code != 200:
                    continue

                data = resp.json()
                total = data.get("totalResults", 0)

                if total == 0:
                    continue

                for cve_item in data.get("vulnerabilities", [])[:5]:
                    cve_data = cve_item.get("cve", {})
                    cve_id = cve_data.get("id", "Unknown")

                    # Extraer descripción en español o inglés
                    descriptions = cve_data.get("descriptions", [])
                    desc_text = "Sin descripción disponible."
                    for d in descriptions:
                        if d.get("lang") == "es":
                            desc_text = d.get("value", desc_text)
                            break
                        if d.get("lang") == "en":
                            desc_text = d.get("value", desc_text)

                    # Extraer severidad CVSS
                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(metric_key, [])
                        if metric_list:
                            cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0)
                            break

                    severity = Severity.INFO
                    if cvss_score >= 9.0:
                        severity = Severity.CRITICAL
                    elif cvss_score >= 7.0:
                        severity = Severity.HIGH
                    elif cvss_score >= 4.0:
                        severity = Severity.MEDIUM
                    elif cvss_score > 0:
                        severity = Severity.LOW

                    vulns.append(Vulnerability(
                        name=f"NVD: {cve_id}",
                        description=(
                            f"[NVD API] {desc_text[:200]}"
                        ),
                        severity=severity,
                        target_url=url,
                        payload=f"{cpe_vendor}/{version} → CVSS {cvss_score}"
                    ))

                logger.info(
                    f"🌐 NVD API: {total} CVE(s) encontrados para {cpe_vendor}/{version}"
                )

            except requests.RequestException:
                logger.debug(f"NVD API no disponible para {cpe_vendor}/{version}")
            except Exception as e:
                logger.debug(f"Error parsing NVD response: {e}")

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
