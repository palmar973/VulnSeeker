import re
import logging
from typing import List
from urllib.parse import urljoin

import requests

from core.scanner_types import ScannerModule, Target, Vulnerability
from core.models import Severity

logger = logging.getLogger("VulnSeeker")


class EmailHarvester(ScannerModule):
    @property
    def name(self) -> str:
        return "📧 Email Harvester"

    @property
    def description(self) -> str:
        return "Recolecta correos públicos para evaluar superficie de Ingeniería Social."

    def run(self, target: Target) -> List[Vulnerability]:
        emails: set[str] = set()
        candidate_paths = ["", "/contact", "/about", "/equipo"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        def fetch(url: str) -> str:
            try:
                resp = requests.get(url, headers=headers, timeout=8)
                if resp.ok:
                    return resp.text or ""
            except Exception:
                return ""
            return ""

        pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        for path in candidate_paths:
            url = urljoin(target.url, path)
            html = fetch(url)
            if not html:
                continue
            for match in pattern.findall(html):
                if match not in emails:
                    emails.add(match)
                    logger.info(f"📧 Email encontrado: {match}")

        vulns: List[Vulnerability] = []
        if emails:
            desc = f"Correos expuestos: {', '.join(sorted(emails))}"
            vulns.append(
                Vulnerability(
                    name="Email Disclosure",
                    description=desc,
                    severity=Severity.INFO,
                    target_url=target.url,
                    payload=desc,
                )
            )
        return vulns
