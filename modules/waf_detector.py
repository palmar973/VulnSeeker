import logging
import requests
from typing import List
from core.interfaces import ScannerModule
from core.models import Vulnerability, Severity

logger = logging.getLogger("VulnSeeker")

class WAFDetector(ScannerModule):
    @property
    def name(self) -> str:
        return "🛡️ WAF Detector"

    @property
    def description(self) -> str:
        return "Identifica Firewalls Web (Cloudflare, AWS, Akamai) mediante análisis pasivo de headers."

    def run(self, target: 'Target') -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        try:
            logger.info(f"🛡️ WAF Detector: Analizando {target.url} ...")
            response = requests.get(
                target.url,
                timeout=5,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                },
            )
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            cookies = response.cookies.get_dict()
            signatures = {
                'Cloudflare': {'headers': {'server': 'cloudflare', 'cf-ray': None}, 'cookies': ['__cfduid']},
                'AWS WAF': {'headers': {'x-amz-cf-id': None, 'x-amzn-requestid': None}, 'cookies': ['aws-waf']},
                'Akamai': {'headers': {'server': 'akamaighost', 'x-akamai-transformed': None}, 'cookies': []},
                'Imperva Incapsula': {'headers': {'x-iinfo': None, 'x-cdn': 'incapsula'}, 'cookies': ['incap_ses']},
                'F5 BIG-IP': {'headers': {'server': 'big-ip'}, 'cookies': ['bigipserver']},
            }
            detected_wafs = []
            for waf_name, sigs in signatures.items():
                for h_name, h_val in sigs['headers'].items():
                    if h_name in headers and (h_val is None or h_val in headers[h_name]):
                        detected_wafs.append(f"{waf_name} (Header: {h_name})")
                        break
                if waf_name not in str(detected_wafs):
                    for c_name in sigs['cookies']:
                        for cookie in cookies.keys():
                            if c_name in cookie.lower():
                                detected_wafs.append(f"{waf_name} (Cookie: {c_name})")
                                break
            if detected_wafs:
                logger.info(f"✅ WAF DETECTADO: {detected_wafs[0]}")
                vulns.append(
                    Vulnerability(
                        name="WAF Detected",
                        description=f"Se detectó protección de Firewall Web: {', '.join(detected_wafs)}",
                        severity=Severity.INFO,
                        target_url=target.url,
                        payload="Passive Analysis",
                    )
                )
        except Exception as e:
            logger.error(f"❌ Error en WAF Detector: {e}")
        return vulns
