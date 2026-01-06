#!/usr/bin/env python3.14
"""
VulnSeeker Enterprise - FASE 19: EL DETECTIVE.
Fingerprinter inteligente que reconoce Server, Lenguaje y CMS antes del ataque.
"""

import re
import requests
from typing import Dict, List
from pathlib import Path
import logging
from urllib.parse import urljoin

logger = logging.getLogger("VulnSeeker.Fingerprint")


class TechFingerprinter:
    """Detective tecnológico: Server -> Lenguaje -> CMS/Framework."""

    def __init__(self) -> None:
        # Patrones de detección (Firmas digitales)
        self.server_patterns = {
            'nginx': r'(nginx/?[\d.]+|\bnnginx\b)',
            'apache': r'(apache|httpd)',
            'iis': r'(microsoft-iis|IIS)',
            'cloudflare': r'cloudflare',
            'lite_speed': r'litespeed'
        }

        self.powered_by_patterns = {
            'php': r'(php/?[\d.]+)',
            'asp.net': r'(asp.net|aspx?)',
            'express': r'express',
            'django': r'django',
            'rails': r'ruby|rails',
            'python': r'python'
        }

        self.cms_patterns = {
            'wordpress': [
                r'<meta name=["\']generator["\'][^>]*["\']WordPress',
                r'/wp-content/',
                r'/wp-includes/',
                r'wp-json/wp/v2'
            ],
            'joomla': [
                r'<meta name=["\']generator["\'][^>]*["\']Joomla',
                r'/templates/',
                r'/administrator/'
            ],
            'drupal': [
                r'<meta name=["\']Generator["\'][^>]*["\']Drupal',
                r'/sites/default/',
                r'/modules/'
            ],
            'shopify': [
                r'/shopify/',
                r'shopify.*cdn'
            ],
            'laravel': [
                r'laravel_session',
                r'X-SRF-TOKEN'
            ]
        }

        # Rutas comunes para "adivinar" si no hay headers claros
        self.common_paths = [
            '/wp-admin/', '/administrator/', '/sites/', '/themes/', '/modules/'
        ]

    def analyze(self, target_url: str) -> Dict[str, List[str]]:
        """Análisis completo: headers + HTML + paths predictivos."""
        fingerprint = {
            'server': [],
            'powered_by': [],
            'cms_framework': [],
            'confidence': 'LOW'
        }

        try:
            # 1. Headers principales
            headers = self._get_headers(target_url)
            fp_headers = self._analyze_headers(headers)
            fingerprint['server'].extend(fp_headers['server'])
            fingerprint['powered_by'].extend(fp_headers['powered_by'])

            # 2. HTML + Meta Generator
            html = self._get_html(target_url)
            html_fingerprint = self._analyze_html(html)
            fingerprint['cms_framework'].extend(html_fingerprint)

            # 3. Paths predictivos (solo si la confianza es baja)
            if not fingerprint['cms_framework']:
                path_fingerprint = self._analyze_paths(target_url)
                fingerprint['cms_framework'].extend(path_fingerprint)

            # Confidence scoring (Puntaje de certeza)
            total_clues = len(fingerprint['server']) + len(fingerprint['powered_by']) + len(
                fingerprint['cms_framework'])
            fingerprint['confidence'] = 'HIGH' if total_clues >= 3 else 'MEDIUM' if total_clues >= 1 else 'LOW'

            # Limpiar duplicados
            for key in fingerprint:
                if isinstance(fingerprint[key], list):
                    fingerprint[key] = list(set(fingerprint[key]))

        except Exception as e:
            logger.warning(f"Fingerprint falló en {target_url}: {e}")
            fingerprint['confidence'] = 'FAILED'

        return fingerprint

    def _get_headers(self, target_url: str) -> Dict[str, str]:
        try:
            resp = requests.head(target_url, timeout=5, headers={'User-Agent': 'VulnSeeker/1.0'}, verify=False)
            return dict(resp.headers)
        except:
            return {}

    def _get_html(self, target_url: str) -> str:
        try:
            resp = requests.get(target_url, timeout=7, headers={'User-Agent': 'VulnSeeker/1.0'}, verify=False)
            return resp.text.lower()
        except:
            return ""

    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, List[str]]:
        result = {'server': [], 'powered_by': []}

        # Server header
        server_header = headers.get('server', '').lower()
        for tech, pattern in self.server_patterns.items():
            if re.search(pattern, server_header):
                result['server'].append(tech.capitalize())

        # X-Powered-By
        powered_header = headers.get('x-powered-by', '').lower()
        for tech, pattern in self.powered_by_patterns.items():
            if re.search(pattern, powered_header):
                result['powered_by'].append(tech.replace('.', ' ').title())

        return result

    def _analyze_html(self, html: str) -> List[str]:
        cms_detected = []
        for cms, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    cms_detected.append(cms.capitalize())
                    break
        return cms_detected

    def _analyze_paths(self, target_url: str) -> List[str]:
        detected = []
        try:
            for path in self.common_paths[:3]:  # Solo probar los 3 más comunes para no ser lento
                test_url = urljoin(target_url, path)
                resp = requests.head(test_url, timeout=3, allow_redirects=True, verify=False)
                if resp.status_code == 200:
                    # Deducción basada en ruta
                    if "wp-" in path: detected.append("WordPress")
                    if "administrator" in path: detected.append("Joomla")
        except:
            pass
        return detected