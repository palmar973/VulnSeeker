import requests
import logging
from urllib.parse import urlparse, parse_qs
from core.models import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.SSRF")

# Parámetros que suelen aceptar URLs o rutas externas
SSRF_PARAMS = [
    "url", "redirect", "next", "dest", "file", "path", "load",
    "fetch", "proxy", "img", "uri", "src", "href", "link",
    "callback", "feed",
]

# Payloads que intentan alcanzar recursos internos
SSRF_PAYLOADS = [
    ("http://127.0.0.1:80", ["127.0.0.1", "localhost", "It works"]),
    ("http://localhost:80", ["127.0.0.1", "localhost", "It works"]),
    ("http://[::1]:80", ["127.0.0.1", "localhost", "It works"]),
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam"]),
    ("http://0.0.0.0:80", ["127.0.0.1", "localhost", "It works"]),
]


class SSRFScanner(ScannerModule):
    """Detecta vulnerabilidades Server-Side Request Forgery (SSRF)
    que permiten a un atacante forzar al servidor a realizar peticiones
    a recursos internos o servicios de metadata."""

    @property
    def name(self) -> str:
        return "SSRF Scanner"

    @property
    def description(self) -> str:
        return "Detecta si la aplicación permite realizar peticiones a recursos internos (SSRF)."

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

        # Filtrar solo los parámetros que parecen aceptar URLs
        ssrf_keys = [k for k in element_params if k.lower() in SSRF_PARAMS]

        if not ssrf_keys:
            return vulns

        base_url = target.url.split("?")[0]

        headers = {"User-Agent": "VulnSeeker/1.0"}
        if target.headers:
            headers.update(target.headers)

        session = requests.Session()

        # Obtener respuesta baseline para comparar
        baseline_text = ""
        try:
            baseline_params = dict(element_params)
            if method == "POST":
                baseline_resp = session.post(
                    base_url, data=baseline_params, timeout=5, headers=headers, verify=False
                )
            else:
                baseline_resp = session.get(
                    base_url, params=baseline_params, timeout=5, headers=headers, verify=False
                )
            baseline_size = len(baseline_resp.text)
            baseline_code = baseline_resp.status_code
            baseline_text = baseline_resp.text
        except Exception:
            baseline_size = 0
            baseline_code = 200

        logger.info(f"🔍 SSRF Scanner: Probando {len(ssrf_keys)} parámetros en {target.url}")

        for param_name in ssrf_keys:
            for payload_url, keywords in SSRF_PAYLOADS:
                try:
                    test_params = dict(element_params)
                    test_params[param_name] = payload_url

                    if method == "POST":
                        resp = session.post(
                            base_url, data=test_params, timeout=5,
                            headers=headers, verify=False
                        )
                    else:
                        resp = session.get(
                            base_url, params=test_params, timeout=5,
                            headers=headers, verify=False
                        )

                    # Verificar si la respuesta contiene indicadores de contenido interno
                    if self._has_ssrf_indicators(resp, keywords, baseline_size, baseline_code, baseline_text):
                        matched = [kw for kw in keywords if kw in resp.text and kw not in baseline_text]
                        vulns.append(Vulnerability(
                            name="Server-Side Request Forgery (SSRF)",
                            description=(
                                f"El parámetro '{param_name}' permite realizar peticiones "
                                f"a recursos internos. Payload: {payload_url}"
                            ),
                            severity=Severity.HIGH,
                            target_url=target.url,
                            evidence=(
                                f"Contenido interno detectado: {matched} | "
                                f"Response code: {resp.status_code} | "
                                f"Response size: {len(resp.text)}"
                            ),
                            payload=f"{param_name}={payload_url}",
                        ))
                        logger.info(f"🔥 ¡SSRF DETECTADO! {param_name}={payload_url}")
                        # Un hit por parámetro es suficiente
                        break

                except requests.RequestException as e:
                    logger.debug(f"Error probando SSRF en {base_url}: {e}")
                except Exception as e:
                    logger.error(f"Error inesperado en SSRF Scanner: {e}")

        return vulns

    @staticmethod
    def _has_ssrf_indicators(
        response: requests.Response,
        keywords: list[str],
        baseline_size: int,
        baseline_code: int,
        baseline_text: str = "",
    ) -> bool:
        """Comprueba si la respuesta muestra signos de SSRF exitoso."""
        # Verificar presencia de palabras clave internas que NO estaban en el baseline
        # (si ya aparecían en la respuesta base, no son fruto del payload).
        for keyword in keywords:
            if keyword in response.text and keyword not in baseline_text:
                return True

        # Diferencia significativa de tamaño respecto al baseline (>50%)
        resp_size = len(response.text)
        if baseline_size > 0:
            size_diff = abs(resp_size - baseline_size) / baseline_size
            if size_diff > 0.5 and resp_size > 100:
                # Si el baseline es pequeño y el tamaño cambia mucho, pero verifiquemos que no sea solo una redirección o error común
                return True

        return False
