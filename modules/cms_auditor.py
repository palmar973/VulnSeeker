import requests
from typing import List
from core.models import ScannerModule, Target, Vulnerability, Severity

class CMSAuditor(ScannerModule):
    @property
    def name(self) -> str:
        return "CMS Auditor (Context-Aware)"

    @property
    def description(self) -> str:
        return "Ejecuta pruebas específicas según el CMS detectado en la Fase 1."

    def run(self, target: Target) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        base = target.url.rstrip("/")
        techs_raw = target.context.get("cms_framework", []) or []
        techs = [str(t).lower() for t in techs_raw]

        try:
            if "wordpress" in techs:
                try:
                    r_users = requests.get(f"{base}/wp-json/wp/v2/users", timeout=5)
                    if r_users.status_code == 200 and "slug" in r_users.text:
                        findings.append(
                            Vulnerability(
                                name="WordPress User Enumeration",
                                severity=Severity.MEDIUM,
                                description="El endpoint REST de usuarios está expuesto y permite enumeración.",
                                target_url=f"{base}/wp-json/wp/v2/users",
                                evidence="slug field present"
                            )
                        )
                except Exception:
                    pass
                try:
                    r_xmlrpc = requests.get(f"{base}/xmlrpc.php", timeout=5)
                    if r_xmlrpc.status_code == 405 or "XML-RPC server accepts POST" in r_xmlrpc.text:
                        findings.append(
                            Vulnerability(
                                name="XML-RPC Interface Exposed",
                                severity=Severity.LOW,
                                description="La interfaz XML-RPC está expuesta y puede ser abusada.",
                                target_url=f"{base}/xmlrpc.php",
                                evidence=str(r_xmlrpc.status_code)
                            )
                        )
                except Exception:
                    pass

            if "joomla" in techs:
                try:
                    r_joomla = requests.get(f"{base}/administrator/manifests/files/joomla.xml", timeout=5)
                    if r_joomla.status_code == 200:
                        findings.append(
                            Vulnerability(
                                name="Joomla Version Disclosure",
                                severity=Severity.LOW,
                                description="El manifiesto de Joomla está accesible y revela la versión.",
                                target_url=f"{base}/administrator/manifests/files/joomla.xml",
                                evidence=str(r_joomla.status_code)
                            )
                        )
                except Exception:
                    pass

            if "drupal" in techs:
                try:
                    r_drupal = requests.get(f"{base}/CHANGELOG.txt", timeout=5)
                    if r_drupal.status_code == 200:
                        findings.append(
                            Vulnerability(
                                name="Drupal Version Disclosure",
                                severity=Severity.LOW,
                                description="El archivo CHANGELOG.txt está accesible y revela la versión.",
                                target_url=f"{base}/CHANGELOG.txt",
                                evidence=str(r_drupal.status_code)
                            )
                        )
                except Exception:
                    pass
        except Exception:
            pass

        return findings
