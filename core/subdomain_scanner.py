#!/usr/bin/env python3.14
"""
VulnSeeker Enterprise - FASE 20: EL CONQUISTADOR (Redundante).
Módulo de descubrimiento pasivo de subdominios.
Fuentes: crt.sh (Primaria) -> HackerTarget (Respaldo).
"""

import requests
import logging
import json
from typing import List
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("VulnSeeker.Subdomain")


class SubdomainScanner:
    """Conquistador OSINT: Encuentra subdominios reales sin tocar el target."""

    def __init__(self, timeout: int = 15, max_workers: int = 10) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def discover(self, target_input: str) -> List[str]:
        domain = self._clean_domain(target_input)
        if not domain:
            return []

        logger.info(f"🌐 Iniciando OSINT para: {domain}")
        found_subdomains = set()

        # 1. INTENTO PRIMARIO: crt.sh
        try:
            logger.info("   👉 Consultando fuente primaria (crt.sh)...")
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for sub in name_value.split('\n'):
                            if self._is_valid(sub, domain):
                                found_subdomains.add(sub.lower())
                except json.JSONDecodeError:
                    logger.warning("⚠️ crt.sh devolvió respuesta no válida.")
        except Exception as e:
            logger.error(f"Error en crt.sh: {e}")

        # 2. INTENTO SECUNDARIO: HackerTarget (Si el primero trajo poco)
        if len(found_subdomains) < 2:
            try:
                logger.info("   👉 Consultando fuente de respaldo (HackerTarget)...")
                url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout)

                if resp.status_code == 200:
                    lines = resp.text.split('\n')
                    for line in lines:
                        # Formato: hostname,ip
                        if ',' in line:
                            sub = line.split(',')[0]
                            if self._is_valid(sub, domain):
                                found_subdomains.add(sub.lower())
            except Exception as e:
                logger.error(f"Error en HackerTarget: {e}")

        if not found_subdomains:
            logger.info("📭 No se encontraron subdominios en ninguna fuente.")
            return []

        # 3. VALIDACIÓN ACTIVA
        candidates = list(found_subdomains)
        logger.info(f"🔍 Validando {len(candidates)} candidatos...")
        return self._validate_live_subdomains(candidates)

    def _clean_domain(self, target: str) -> str:
        target = target.lower().strip()
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        try:
            parsed = urlparse(target)
            hostname = parsed.netloc or parsed.path
            if ':' in hostname: hostname = hostname.split(':')[0]
            parts = hostname.split('.')
            if len(parts) >= 2: return f"{parts[-2]}.{parts[-1]}"
            return hostname
        except:
            return ""

    def _is_valid(self, subdomain: str, domain: str) -> bool:
        """Filtra basura, wildcards y dominios externos."""
        sub = subdomain.strip().lower()
        if '*' in sub or '%' in sub: return False
        if not sub.endswith(domain): return False
        if sub == domain: return False  # Ignorar root domain
        return True

    def _validate_live_subdomains(self, subdomains: List[str]) -> List[str]:
        live = []

        def check(sub):
            try:
                # Probar HTTPS primero (más común hoy día)
                requests.head(f"https://{sub}", timeout=3, verify=False)
                return True
            except:
                try:
                    requests.head(f"http://{sub}", timeout=2, verify=False)
                    return True
                except:
                    return False

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_sub = {executor.submit(check, sub): sub for sub in subdomains}
            for future in as_completed(future_to_sub):
                if future.result():
                    live.append(future_to_sub[future])

        return sorted(live)