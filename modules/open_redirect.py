import requests
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.OpenRedirect")

# Parámetros comúnmente usados para redirecciones
REDIRECT_PARAMS = [
    "url", "redirect", "next", "dest", "destination", "return",
    "returnurl", "return_url", "redirect_uri", "redirect_url",
    "go", "target", "out", "rurl", "redir", "link", "ref",
    "continue", "forward", "path", "callback", "checkout_url",
]

# Payloads que simulan redirección a un dominio externo
PAYLOADS = [
    "http://evil.com",
    "https://evil.com",
    "//evil.com",
    "http://evil.com/%2f..",
]

REDIRECT_CODES = {301, 302, 303, 307, 308}


class OpenRedirectScanner(ScannerModule):
    """Detecta redirecciones abiertas (Open Redirect) que permiten
    enviar al usuario a un sitio externo controlado por un atacante."""

    @property
    def name(self) -> str:
        return "Open Redirect Scanner"

    @property
    def description(self) -> str:
        return "Detecta redirecciones no validadas hacia dominios externos."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        # Obtener parámetros desde el PageElement o desde la URL
        element_params: dict[str, str] = {}
        method = "GET"

        if target.elements:
            element_params = dict(target.elements[0].params)
            method = target.elements[0].method.upper()
        elif "?" in target.url:
            try:
                parsed = urlparse(target.url)
                element_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            except Exception:
                return vulns

        if not element_params:
            return vulns

        # Filtrar solo los parámetros que parecen de redirección
        redirect_keys = [k for k in element_params if k.lower() in REDIRECT_PARAMS]

        if not redirect_keys:
            return vulns

        base_url = target.url.split("?")[0]

        for param_name in redirect_keys:
            for payload in PAYLOADS:
                try:
                    test_params = dict(element_params)
                    test_params[param_name] = payload

                    if method == "POST":
                        resp = requests.post(
                            base_url, data=test_params,
                            allow_redirects=False, timeout=5,
                            headers={"User-Agent": "VulnSeeker/1.0"}
                        )
                    else:
                        resp = requests.get(
                            base_url, params=test_params,
                            allow_redirects=False, timeout=5,
                            headers={"User-Agent": "VulnSeeker/1.0"}
                        )

                    if resp.status_code in REDIRECT_CODES:
                        location = resp.headers.get("Location", "")
                        if self._is_external_redirect(location, payload):
                            vulns.append(Vulnerability(
                                name="Open Redirect",
                                description=(
                                    f"El parámetro '{param_name}' redirige a un dominio externo "
                                    f"sin validación. Payload: {payload} → Location: {location}"
                                ),
                                severity=Severity.MEDIUM,
                                target_url=target.url,
                                payload=f"{param_name}={payload}"
                            ))
                            # Un hit por parámetro es suficiente
                            break

                except requests.RequestException as e:
                    logger.debug(f"Error probando redirect en {base_url}: {e}")
                except Exception as e:
                    logger.error(f"Error inesperado en Open Redirect: {e}")

        return vulns

    @staticmethod
    def _is_external_redirect(location: str, payload: str) -> bool:
        """Valida que el Location realmente apunte al dominio inyectado."""
        if not location:
            return False
        # Verificar que evil.com aparece en el host del Location
        try:
            parsed = urlparse(location)
            return "evil.com" in (parsed.netloc or "")
        except Exception:
            return payload in location
