import dns.resolver
import requests
import urllib.parse
import logging
from typing import List
from core.models import ScannerModule, Target, Vulnerability, Severity

logger = logging.getLogger("VulnSeeker")


class SubdomainTakeover(ScannerModule):
    @property
    def name(self) -> str:
        return "☁️ Subdomain Takeover"

    @property
    def description(self) -> str:
        return "Detecta subdominios que apuntan a servicios de terceros no reclamados (S3, GitHub Pages, etc.)."

    def run(self, target: Target) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        signatures = {
            'GitHub Pages': {'cname': 'github.io', 'error': "There isn't a GitHub Pages site here"},
            'AWS S3': {'cname': 's3.amazonaws.com', 'error': "NoSuchBucket"},
            'Heroku': {'cname': 'herokuapp.com', 'error': "No such app"},
            'Pantheon': {'cname': 'pantheonsite.io', 'error': "404 error unknown site"},
            'Tumblr': {'cname': 'tumblr.com', 'error': "Whatever you were looking for doesn't currently exist"},
            'Shopify': {'cname': 'myshopify.com', 'error': "Sorry, this shop is currently unavailable"}
        }

        parsed_url = urllib.parse.urlparse(target.url)
        main_domain = parsed_url.hostname

        domains_to_check = [main_domain]
        if target.context and "subdomains" in target.context:
            domains_to_check.extend(target.context["subdomains"])

        domains_to_check = list(set([d for d in domains_to_check if d]))

        logger.info(f"☁️ Subdomain Takeover: Analizando {len(domains_to_check)} dominios...")

        for domain in domains_to_check:
            try:
                try:
                    answers = dns.resolver.resolve(domain, 'CNAME')
                    cname_record = str(answers[0].target).strip('.').lower()
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
                    continue

                for service, signature in signatures.items():
                    if signature['cname'] in cname_record:
                        logger.info(f"⚠️ Posible {service} detectado en {domain} (CNAME: {cname_record})")

                        if domain == main_domain:
                            check_url = target.url
                        else:
                            check_url = f"http://{domain}"

                        logger.info(f"🔍 DEBUG: Verificando contenido en {check_url}...")

                        try:
                            resp = requests.get(check_url, timeout=5, verify=False, allow_redirects=True)
                            content = resp.text

                            if signature['error'] in content:
                                logger.info(f"🚨 SUBDOMAIN TAKEOVER DETECTADO: {domain}")

                                vulns.append(Vulnerability(
                                    name=f"Subdomain Takeover ({service})",
                                    description=f"El dominio {domain} apunta a {cname_record} pero el recurso no existe. Firma encontrada: '{signature['error']}'.",
                                    severity=Severity.HIGH,
                                    target_url=check_url,
                                    payload=f"CNAME: {cname_record}"
                                ))
                        except Exception as e:
                            logger.error(f"❌ Error conectando a {check_url}: {e}")

            except Exception:
                pass

        return vulns