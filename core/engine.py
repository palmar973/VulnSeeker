import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
# Necesario para extraer el dominio antes del recon de subdominios
from urllib.parse import urlparse
from core.models import Target, Vulnerability, PageElement, ScannerModule
from core.crawler import WebCrawler
from core.config import GlobalConfig
from core.fingerprinter import TechFingerprinter
from core.subdomain_scanner import SubdomainScanner

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class VulnSeekerEngine:
    """Orquestador Enterprise con Fingerprint + Subdomain Discovery."""

    def __init__(self, enable_subdomains: bool = True, config: dict | None = None) -> None:
        default_config = {
            "threads": 10,
            "user_agent": GlobalConfig.USER_AGENT,
            "enable_subdomains": True if config is None else True
        }
        if config is None:
            config = default_config
            config["enable_subdomains"] = enable_subdomains
        else:
            cfg = default_config.copy()
            cfg.update(config)
            config = cfg

        self.config = config
        self.modules: List[ScannerModule] = []
        self.results: List[Vulnerability] = []
        self.fingerprint_data: str = "Unknown"
        self.subdomain_data: List[str] = []
        self.tech_context: dict = {}
        self.enable_subdomains = self.config.get("enable_subdomains", True)
        logger.info("⚙️ VulnSeeker Engine inicializado (Subdomains: ON)" if self.enable_subdomains
                    else "⚙️ VulnSeeker Engine inicializado (Subdomains: OFF)")

    def register_module(self, module: ScannerModule) -> None:
        if not isinstance(module, ScannerModule):
            raise TypeError(f"El objeto {type(module)} no cumple con la interfaz ScannerModule.")
        self.modules.append(module)
        logger.debug(f"📦 Módulo registrado: {module.name}")

    def scan(self, start_url: str, crawl: bool = True) -> List[Vulnerability]:
        """Punto de entrada principal con recon OSINT expandido."""

        self.results = []  # Resetear resultados de escaneos anteriores
        if not start_url.startswith(('http://', 'https://')):
            start_url = 'http://' + start_url

        logger.info(f"🎯 --- AUDITORÍA ENTERPRISE: {start_url} ---")

        # FASE 0: SUBDOMAIN DISCOVERY (FASE 20)
        if self.config.get("enable_subdomains", True):
            self._run_subdomain_discovery(start_url)

        # FASE 1: FINGERPRINTING (Detective)
        try:
            logger.info("🕵️‍♂️ Análisis tecnológico activo...")
            fp = TechFingerprinter()
            tech_context = fp.analyze(start_url)

            tech_parts = []
            if tech_context['server']: tech_parts.append(f"Server: {', '.join(tech_context['server'])}")
            if tech_context['powered_by']: tech_parts.append(f"Backend: {', '.join(tech_context['powered_by'])}")
            if tech_context['cms_framework']: tech_parts.append(f"CMS: {', '.join(tech_context['cms_framework'])}")

            self.fingerprint_data = " | ".join(tech_parts) if tech_parts else "Tecnología Genérica"
            self.tech_context = tech_context or {}
            logger.info(f"🔬 Fingerprint: {self.fingerprint_data}")
        except Exception as e:
            logger.error(f"⚠️ Fingerprint falló: {e}")
            self.fingerprint_data = "Error en análisis"
            self.tech_context = {}

        # FASE 1.5: AUTO-LOGIN (si es DVWA u otra plataforma soportada)
        self._check_and_perform_autologin(start_url)

        # FASE 2: CRAWLING
        target_elements: List[PageElement] = []
        if crawl:
            logger.info("🕷️ Crawler estructural activo...")
            cookies = self.config.get("cookies", {})
            crawler = WebCrawler(start_url, max_pages=GlobalConfig.MAX_CRAWL_PAGES, cookies=cookies)
            target_elements = crawler.start()

            # FASE 2.5: API DISCOVERY (SPAs/REST sin navegador)
            # El crawler estructural es ciego ante SPAs (Angular/React/Vue): los
            # endpoints viven en JS/API, no en el HTML. Recuperamos esa superficie
            # parseando spec OpenAPI + extrayendo rutas de los bundles JS.
            target_elements.extend(self._discover_api_endpoints(start_url, target_elements))
        else:
            target_elements = [PageElement(url=start_url, method="GET")]

        logger.info(f"📍 {len(target_elements)} endpoints identificados.")

        # FASE 3: ATAQUE MULTIHILO
        if target_elements:
            logger.info(f"⚔️ Ataque coordinado: {len(self.modules)} módulos, {self.config.get('threads', 10)} hilos.")
            with ThreadPoolExecutor(max_workers=self.config.get("threads", 10)) as executor:
                future_to_element = {
                    executor.submit(self._analyze_single_element, element): element
                    for element in target_elements
                }

                for future in as_completed(future_to_element):
                    try:
                        vulns = future.result()
                        if vulns:
                            self.results.extend(vulns)
                    except Exception as e:
                        element = future_to_element[future]
                        logger.error(f"💥 Error hilo {element.url}: {e}")
        else:
            logger.warning("⚠️ No se encontraron endpoints para atacar. Verifica la URL.")

        logger.info(f"🏁 Auditoría completada: {len(self.results)} hallazgos brutos.")

        # Deduplicación: eliminar hallazgos idénticos (mismo nombre + URL + payload)
        seen = set()
        unique_results = []
        for v in self.results:
            key = (v.name, v.target_url, getattr(v, 'payload', ''))
            if key not in seen:
                seen.add(key)
                unique_results.append(v)

        dedup_count = len(self.results) - len(unique_results)
        if dedup_count > 0:
            logger.info(f"🔄 Deduplicación: {dedup_count} duplicados eliminados.")
        self.results = unique_results

        logger.info(f"📊 Resultado final: {len(self.results)} vulnerabilidades únicas.")
        logger.info(f"🌐 Subdominios expandidos: {len(self.subdomain_data)}")
        return self.results

    def _run_subdomain_discovery(self, start_url: str) -> None:
        """Ejecuta el Conquistador OSINT."""
        try:
            parsed = urlparse(start_url)
            domain = parsed.netloc or parsed.path  # Maneja casos raros

            logger.info(f"🌐 Recon OSINT: {domain} (crt.sh Certificate Transparency)")

            scanner = SubdomainScanner()
            # Pasamos la URL completa; el scanner extrae el dominio base internamente
            self.subdomain_data = scanner.discover(start_url)

            if self.subdomain_data:
                logger.info(f"🎉 CONQUISTADOR: {len(self.subdomain_data)} subdominios LIVE:")
                for sub in self.subdomain_data[:5]:
                    logger.info(f"   👉 {sub}")
                if len(self.subdomain_data) > 5:
                    logger.info(f"   ...y {len(self.subdomain_data) - 5} más")
            else:
                logger.info("📭 No se encontraron subdominios adicionales.")

        except Exception as e:
            logger.error(f"⚠️ Error Subdomain Scanner: {e}")
            self.subdomain_data = []

    def _discover_api_endpoints(self, start_url: str, existing: List[PageElement]) -> List[PageElement]:
        """Descubre endpoints de API (SPAs/REST) sin navegador y los devuelve sin duplicar.
        En apps server-rendered (DVWA) no hay spec ni rutas de API en JS → devuelve []."""
        try:
            from core.api_discovery import ApiEndpointDiscovery
            cookies = self.config.get("cookies", {})
            headers = {'User-Agent': self.config.get("user_agent", GlobalConfig.USER_AGENT)}
            api_elements = ApiEndpointDiscovery(start_url, headers=headers, cookies=cookies).discover()
        except Exception as e:
            logger.error(f"⚠️ API discovery falló: {e}")
            return []

        seen = {(e.url, e.method) for e in existing}
        nuevos = [e for e in api_elements if (e.url, e.method) not in seen]
        if nuevos:
            logger.info(f"🔌 API discovery: +{len(nuevos)} endpoints REST añadidos al arsenal "
                        f"(el crawler estructural había mapeado {len(existing)}).")
        return nuevos

    def _analyze_single_element(self, element: PageElement) -> List[Vulnerability]:
        """Análisis individual por hilo."""
        findings: List[Vulnerability] = []
        headers = {'User-Agent': self.config.get("user_agent", GlobalConfig.USER_AGENT)}

        # Inyectar cookies como header Cookie para módulos que usan requests
        cookies = self.config.get("cookies", {})
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        target = Target(
            url=element.url,
            method=element.method,
            headers=headers,
            elements=[element],
            context=self.tech_context
        )

        for module in self.modules:
            try:
                vulns = module.run(target)
                if vulns:
                    findings.extend(vulns)
            except Exception as e:
                logger.error(f"💥 Módulo {module.name} falló en {element.url}: {e}")

        return findings

    def _check_and_perform_autologin(self, start_url: str) -> None:
        """Intenta auto-login si el objetivo es una instancia de DVWA."""
        try:
            import requests
            from bs4 import BeautifulSoup
            import time
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            parsed = urlparse(start_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            login_url = f"{base_url.rstrip('/')}/login.php"

            # 1. Comprobar si el objetivo es DVWA
            logger.info(f"🔑 Verificando si el objetivo requiere autenticación DVWA: {login_url}")
            try:
                r = requests.get(login_url, timeout=3, verify=False)
                if not (r.status_code == 200 and "Login :: Damn Vulnerable Web Application" in r.text):
                    logger.debug("El objetivo no parece ser una instancia estándar de DVWA o no requiere auto-login.")
                    return
            except Exception:
                logger.debug("No se pudo conectar a la página de login para verificar si es DVWA.")
                return

            # 2. Comprobar si la sesión actual configurada ya es válida
            cookies = self.config.get("cookies", {})
            if cookies and "PHPSESSID" in cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                test_headers = {'User-Agent': self.config.get("user_agent", GlobalConfig.USER_AGENT), 'Cookie': cookie_str}
                try:
                    test_r = requests.get(f"{base_url.rstrip('/')}/index.php", headers=test_headers, timeout=3, allow_redirects=False, verify=False)
                    if test_r.status_code == 200 and "login.php" not in test_r.text and "Login :: Damn" not in test_r.text:
                        logger.info("✅ Sesión existente válida detectada. Omitiendo auto-login.")
                        return
                except Exception:
                    pass

            logger.info("🤖 DVWA Detectado. Iniciando auto-login para garantizar sesión activa...")

            # 3. Intentar auto-login con hasta 3 reintentos
            for attempt in range(1, 4):
                try:
                    session = requests.Session()

                    # Inicialización automática de la base de datos si es necesario
                    if attempt == 1:
                        try:
                            setup_url = f"{base_url.rstrip('/')}/setup.php"
                            r_setup = session.get(setup_url, timeout=5, verify=False)
                            if r_setup.status_code == 200 and "create_db" in r_setup.text:
                                logger.info("⚙️ Detectada base de datos sin inicializar en DVWA. Creando/reseteando base de datos automáticamente...")
                                soup_setup = BeautifulSoup(r_setup.text, 'html.parser')
                                setup_token_input = soup_setup.find('input', {'name': 'user_token'})
                                setup_data = {"create_db": "Create / Reset Database"}
                                if setup_token_input:
                                    setup_data["user_token"] = setup_token_input.get('value')
                                session.post(setup_url, data=setup_data, timeout=5, verify=False)
                        except Exception as e:
                            logger.debug(f"Error inicializando base de datos en setup.php: {e}")

                    r_login = session.get(login_url, timeout=5, verify=False)
                    soup = BeautifulSoup(r_login.text, 'html.parser')
                    user_token_input = soup.find('input', {'name': 'user_token'})

                    if not user_token_input:
                        logger.warning(f"⚠️ Intento {attempt}/3: No se encontró token CSRF (user_token). Reintentando...")
                        time.sleep(1)
                        continue

                    user_token = user_token_input.get('value')
                    data = {
                        'username': 'admin',
                        'password': 'password',
                        'Login': 'Login',
                        'user_token': user_token
                    }

                    r2 = session.post(login_url, data=data, timeout=5, verify=False)
                    if "login.php" not in r2.url and "Login :: Damn" not in r2.text:
                        logger.info(f"✅ Auto-login en DVWA exitoso (intento {attempt}).")

                        # Establecer nivel de seguridad a 'low'
                        security_url = f"{base_url.rstrip('/')}/security.php"
                        r_sec = session.get(security_url, timeout=5, verify=False)
                        soup_sec = BeautifulSoup(r_sec.text, 'html.parser')
                        sec_token_input = soup_sec.find('input', {'name': 'user_token'})

                        sec_data = {
                            'security': 'low',
                            'seclev_submit': 'Submit'
                        }
                        if sec_token_input:
                            sec_data['user_token'] = sec_token_input.get('value')

                        session.post(security_url, data=sec_data, timeout=5, verify=False)
                        logger.info("🛡️ Nivel de seguridad de DVWA configurado a: LOW")

                        # Actualizar cookies en el config del motor
                        autologin_cookies = session.cookies.get_dict()
                        if "cookies" not in self.config:
                            self.config["cookies"] = {}
                        self.config["cookies"].update(autologin_cookies)
                        logger.info(f"🍪 Sesión activa configurada: {self.config['cookies']}")
                        return
                    else:
                        logger.warning(f"⚠️ Intento {attempt}/3: El login falló (credenciales incorrectas o bloqueadas). Reintentando...")
                        time.sleep(1)
                except Exception as ex:
                    logger.warning(f"⚠️ Intento {attempt}/3: Error de conexión durante el login: {ex}")
                    time.sleep(1)

            logger.error("❌ Auto-login falló tras 3 intentos. Se continuará el escaneo con las cookies actuales.")

        except Exception as e:
            logger.debug(f"No se pudo realizar el chequeo de auto-login: {e}")

    # GETTERS para UI/DB

