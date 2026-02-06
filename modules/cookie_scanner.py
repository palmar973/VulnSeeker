import requests
import logging
from core.scanner_types import ScannerModule, Vulnerability, Target, Severity

logger = logging.getLogger("VulnSeeker.CookieScanner")


class CookieScanner(ScannerModule):
    """
    Escáner de seguridad de Cookies.
    Verifica banderas Secure, HttpOnly y SameSite.
    """

    @property
    def name(self) -> str:
        return "Cookie Security Scanner"

    @property
    def description(self) -> str:
        return "Audita banderas de seguridad en cookies de sesión (Secure, HttpOnly)."

    def run(self, target: Target) -> list[Vulnerability]:
        vulns = []
        logger.info(f"🍪 Analizando seguridad de Cookies en: {target.url}")

        try:
            session = requests.Session()

            # Headers de navegador para no levantar sospechas
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            if target.headers:
                headers.update(target.headers)

            try:
                # verify=False es vital para entornos locales
                response = session.get(target.url, headers=headers, allow_redirects=True, timeout=10, verify=False)
            except Exception as e:
                logger.warning(f"⚠️ No se pudo conectar para ver cookies: {e}")
                return []

            # Extraemos TODAS las cookies acumuladas
            all_cookies = session.cookies

            if not all_cookies:
                logger.info("🍪 No se detectaron cookies en la respuesta.")
                return []

            logger.info(f"🍪 Se encontraron {len(all_cookies)} cookies. Analizando banderas...")

            for cookie in all_cookies:
                missing_flags = []

                # 1. Chequeo SECURE
                if not cookie.secure:
                    missing_flags.append("Secure")

                # 2. Chequeo HTTPONLY
                is_httponly = False
                if cookie.has_nonstandard_attr('HttpOnly'):
                    is_httponly = True
                elif getattr(cookie, '_rest', {}).get('HttpOnly'):
                    is_httponly = True
                elif 'HttpOnly' in getattr(cookie, '_rest', {}).keys():
                    is_httponly = True

                if not is_httponly:
                    missing_flags.append("HttpOnly")

                # 3. Reportar si falta algo
                if missing_flags:
                    flags_str = ", ".join(missing_flags)

                    # HttpOnly pesa más por riesgo de robo de sesión
                    sev = Severity.HIGH if "HttpOnly" in missing_flags else Severity.MEDIUM

                    desc = (f"La cookie de sesión '{cookie.name}' es insegura.\n"
                            f"❌ Banderas faltantes: {flags_str}.\n"
                            f"⚠️ Riesgo: Robo de sesión (XSS) o Sniffing.")

                    v = Vulnerability(
                        name=f"Cookie Security: {cookie.name}",
                        severity=sev,
                        description=desc,
                        target_url=target.url,
                        evidence=f"Set-Cookie: {cookie.name}=...; (Missing: {flags_str})",
                        payload=None
                    )
                    vulns.append(v)
                    logger.info(f"🚨 Vulnerabilidad detectada en cookie: {cookie.name}")

        except Exception as e:
            logger.error(f"💥 Error en CookieScanner: {e}")

        return vulns