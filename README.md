<div align="center">

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗███████╗███████╗██╗  ██╗███████╗██████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗█████╗  █████╗  █████╔╝ █████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██╔══╝  ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║███████╗███████╗██║  ██╗███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

[![CI — Tests](https://github.com/palmar973/VulnSeeker/actions/workflows/ci.yml/badge.svg)](https://github.com/palmar973/VulnSeeker/actions/workflows/ci.yml)

**Escáner Modular de Vulnerabilidades Web**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-194%20passing-brightgreen?logo=pytest&logoColor=white)]()
[![Modules](https://img.shields.io/badge/Modules-25%20scanners-orange?logo=shield&logoColor=white)]()
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-8%2F10-red?logo=owasp&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![AI](https://img.shields.io/badge/AI-Llama%203.3%2070B-purple?logo=meta)](https://groq.com/)
[![NVD](https://img.shields.io/badge/NVD-API%202.0-yellow?logo=nist&logoColor=white)](https://nvd.nist.gov/)

</div>

---

## 🔍 ¿Qué es VulnSeeker?

**VulnSeeker** es un framework DAST (Dynamic Application Security Testing) avanzado, desarrollado en Python, diseñado para realizar auditorías de seguridad automatizadas de forma integral. A diferencia de escáneres básicos que se limitan a un solo vector de ataque, VulnSeeker orquesta **25 módulos independientes** de análisis — desde inyecciones SQL y XSS hasta reconocimiento OSINT de subdominios, consulta de CVEs en tiempo real contra la NVD del NIST, y análisis con Inteligencia Artificial.

El sistema opera bajo una arquitectura modular extensible donde cada módulo hereda de la clase base `ScannerModule` y se registra en el motor central, permitiendo agregar nuevas capacidades de escaneo sin modificar el núcleo del sistema.

### ¿Por qué VulnSeeker?

- **Cobertura integrada.** VulnSeeker ejecuta una cadena completa: reconocimiento → fingerprinting → crawling → descubrimiento API-aware → ataque multihilo → deduplicación → análisis IA → reporte.
- **Descubrimiento API-aware (SPAs).** Cuando el objetivo es una Single-Page Application (Angular/React/Vue) cuyo crawling estático no revela endpoints, VulnSeeker recupera la superficie de API parseando la especificación OpenAPI/Swagger y extrayendo rutas `/api/` y `/rest/` de los *bundles* JavaScript —sin navegador *headless*— y ataca también cuerpos JSON.
- **Robustez ante falsos positivos.** Detecta respuestas *catch-all* (soft-404) para no reportar archivos inexistentes en servidores que responden 200 a todo (típico de SPAs), y valida contra *baseline* en los módulos de inyección.
- **8/10 categorías del OWASP Top 10 (2021).** Las 2 restantes (A08, A09) no son evaluables externamente mediante DAST.
- **Inteligencia Artificial integrada.** Llama 3.3 70B realiza un análisis contextual de los hallazgos técnicos y los prioriza según el riesgo de negocio.
- **CVEs en tiempo real.** Integración con la API 2.0 del NIST NVD para consultar vulnerabilidades conocidas asociadas a las tecnologías detectadas.
- **194 tests unitarios.** Suite completa con `pytest` y pipeline CI/CD en GitHub Actions.
- **Validado contra el OWASP Benchmark.** Medición cuantitativa con *ground truth* etiquetado: Índice de Youden 0.68 sobre el subconjunto atacable (SQLi 0.89, XSS 0.87, Precisión 0.95), reportado con honestidad metodológica.
- **Persistencia histórica.** Cada escaneo se almacena en SQLite, permitiendo análisis de tendencias y comparación entre auditorías.

---

## ⚡ Módulos de Detección

### Inyección y Ejecución (A03 + A10 — Injection / SSRF)

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **SQL Injection** | SQLi basada en errores (MySQL, PostgreSQL, Oracle, MSSQL, SQLite/ORM), ciega *time-based* e inyección en cuerpos JSON de APIs REST | 🔴 CRITICAL |
| **Cross-Site Scripting** | Identificación de XSS reflejado mediante inyección de canarios | 🟠 HIGH |
| **Command Injection** | Detección de ejecución remota de comandos (RCE) en parámetros | 🔴 CRITICAL |
| **Local File Inclusion** | Pruebas de traversal de directorios para lectura de archivos locales | 🔴 HIGH |
| **Remote File Inclusion** | Detección de inclusión de archivos remotos en aplicaciones web | 🔴 HIGH |
| **SSRF Scanner** | Detección heurística in-band de Server-Side Request Forgery | 🔴 HIGH |

### Control de Acceso y Autenticación (A01 + A07)

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **Open Redirect** | Detección de redirecciones abiertas explotables | 🟠 HIGH |
| **CORS Scanner** | Análisis de políticas Cross-Origin mal configuradas | 🟡 MEDIUM |
| **CSRF Auditor** | Verificación de protección anti-falsificación en formularios | 🟡 MEDIUM |
| **Brute Force Detector** | Detección de endpoints sin protección contra fuerza bruta | 🟠 HIGH |
| **Weak Session Auditor** | Auditoría de gestión de sesiones (entropía, rotación, tokens) | 🟠 HIGH |

### Configuración y Hardening (A05 — Security Misconfiguration)

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **Header Analyzer** | Evaluación de cabeceras de seguridad (CSP, HSTS, X-Frame-Options, etc.) | 🟡 MEDIUM |
| **Dir Listing Detector** | Detección de listado de directorios habilitado | 🟡 MEDIUM |
| **HTTP Method Scanner** | Identificación de métodos HTTP peligrosos habilitados (PUT, DELETE, TRACE) | 🟡 MEDIUM |
| **Exposure Scanner** | Detección de archivos sensibles expuestos (.env, .git, backups) | 🟠 HIGH |
| **Path Fuzzer** | Descubrimiento de rutas y archivos ocultos mediante diccionarios | 🟡 MEDIUM |

### Componentes Vulnerables y Criptografía (A02 + A06)

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **CVE Lookup** | Base de datos local + consulta en vivo a NVD API 2.0 del NIST | 🔴 CRITICAL |
| **TLS Checker** | Validación de certificados SSL/TLS, protocolos y cifrados débiles | 🟠 HIGH |
| **Sensitive Data Scanner** | Detección de datos sensibles expuestos (emails, tokens, API keys) | 🟠 HIGH |

### Diseño Inseguro (A04)

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **File Upload Detector** | Detección de formularios de subida de archivos sin validación | 🟠 HIGH |

### Reconocimiento y Análisis

| Módulo | Descripción |
|--------|-------------|
| **Web Crawler** | Explorador estructural que mapea URLs, formularios y puntos de entrada con soporte de autenticación |
| **API Endpoint Discovery** | Recupera endpoints de API REST en SPAs sin navegador: parseo de OpenAPI/Swagger + extracción de rutas en *bundles* JavaScript |
| **Tech Fingerprinter** | Identificación de servidor, lenguaje backend, CMS/Framework y versiones |
| **Subdomain Scanner** | Descubrimiento pasivo OSINT vía crt.sh y HackerTarget con validación de subdominios live |
| **Port Scanner** | Escaneo de puertos TCP abiertos con identificación de servicios |

### Inteligencia Artificial

| Característica | Detalle |
|---------------|---------|
| **Modelo** | Llama 3.3 70B vía Groq API |
| **Función** | Generación de informes ejecutivos con análisis de riesgo de negocio |
| **Output** | Nivel de riesgo global, top amenazas, plan de acción inmediato (48h) y recomendaciones estratégicas |

### Reportes

- 📄 **PDF profesional** con portada, gráficos de severidad (pie + barras), tabla de hallazgos y resumen IA
- 📊 **JSON** estructurado para integración con otras herramientas
- 📋 **CSV** compatible con Excel para análisis manual
- 🗄️ **SQLite** con historial completo de escaneos, exportable y consultable

---

## 🏗️ Arquitectura

```
VulnSeeker/
├── core/                         # Núcleo del sistema
│   ├── engine.py                 # Orquestador principal (multihilo)
│   ├── scanner_types.py          # Tipos base: Target, Vulnerability, ScannerModule
│   ├── models.py                 # Estructuras de datos compartidas
│   ├── config.py                 # Configuración global centralizada
│   ├── crawler.py                # Web Crawler con autenticación por cookies
│   ├── api_discovery.py          # Descubridor de endpoints API (SPAs, sin navegador)
│   ├── soft404.py                # Detección de respuestas catch-all (anti-FP)
│   ├── fingerprinter.py          # Fingerprinting tecnológico (Server/CMS/Backend)
│   ├── subdomain_scanner.py      # OSINT de subdominios (crt.sh + HackerTarget)
│   ├── module_registry.py        # Registro centralizado de los 25 módulos
│   └── db_manager.py             # Persistencia SQLite (Singleton)
│
├── modules/                      # 25 módulos de escaneo independientes
│   ├── sqli_module.py            # SQL Injection (Error-Based)
│   ├── xss_module.py             # Reflected XSS
│   ├── cmd_injection.py          # Command Injection / RCE
│   ├── lfi_scanner.py            # Local File Inclusion
│   ├── rfi_scanner.py            # Remote File Inclusion
│   ├── open_redirect.py          # Open Redirect
│   ├── cors_scanner.py           # CORS Misconfiguration
│   ├── csrf_auditor.py           # Cross-Site Request Forgery
│   ├── cve_lookup.py             # CVE Lookup (Local DB + NVD API 2.0)
│   ├── tls_checker.py            # TLS/SSL Certificate Analyzer
│   ├── header_analyzer.py        # HTTP Security Headers
│   ├── dir_listing_detector.py   # Directory Listing Detection
│   ├── http_method_scanner.py    # Dangerous HTTP Methods
│   ├── cookie_scanner.py         # Cookie Security Audit
│   ├── exposure_scanner.py       # Sensitive File Exposure
│   ├── path_fuzzer.py            # Path Fuzzing / Discovery
│   ├── port_scanner.py           # TCP Port Scanner
│   ├── sensitive_data_scanner.py # Sensitive Data Exposure (PII, tokens)
│   ├── file_upload_detector.py   # Insecure File Upload Detection
│   ├── brute_force_detector.py   # Brute Force Protection Audit
│   ├── weak_session_auditor.py   # Session Management Audit
│   ├── waf_detector.py           # WAF Detection
│   ├── cms_auditor.py            # CMS-Specific Vulnerabilities
│   ├── email_harvester.py        # Email Address Discovery
│   ├── ssrf_scanner.py           # Server-Side Request Forgery (SSRF)
│   └── ai_analyst.py             # AI Analyst (Groq / Llama 3.3 70B, servicio auxiliar)
│
├── ui/                           # Interfaz gráfica
│   └── main_window.py            # GUI completa (CustomTkinter + Matplotlib)
│
├── reports/                      # Sistema de reportes
│   ├── report_generator.py       # Exportador JSON/CSV
│   └── pdf_generator.py          # Generador PDF (ReportLab + gráficos)
│
├── tests/                        # 194 tests unitarios (pytest)
│   ├── test_sqli.py
│   ├── test_xss.py
│   ├── test_cmd_injection.py
│   ├── test_cve_lookup.py
│   ├── ...                       # 31 archivos de test
│   └── test_weak_session.py
│
├── tools/                        # Utilidades de evaluación cuantitativa
│   ├── benchmark_scorer.py       # Métricas vs OWASP Benchmark (TPR/FPR/Youden)
│   └── benchmark_runner.py       # Driver: enumera y ataca los casos del Benchmark
│
├── .github/workflows/ci.yml     # CI/CD Pipeline (GitHub Actions)
├── tesis/                       # Documento de tesis (LaTeX + PDF)
│   └── main.tex / main.pdf
├── main.py                      # Punto de entrada CLI
├── gui.py                       # Punto de entrada GUI
├── requirements.txt             # Dependencias del proyecto
└── requirements-dev.txt         # Dependencias de desarrollo (pytest)
```

### Flujo de Ejecución

```
[URL Objetivo]
      │
      ▼
┌─────────────────┐
│ Subdomain OSINT  │ ← crt.sh + HackerTarget
└────────┬────────┘
         ▼
┌─────────────────┐
│  Fingerprinting  │ ← Headers + HTML + Paths predictivos
└────────┬────────┘
         ▼
┌─────────────────┐
│    Web Crawler   │ ← URLs + Formularios + Parámetros (con autenticación)
└────────┬────────┘
         ▼
┌──────────────────────────────────────────────┐
│     ATAQUE MULTIHILO (25 módulos en paralelo)│
│  ┌────────┐ ┌────────┐ ┌──────────────────┐ │
│  │ SQLi   │ │  XSS   │ │ Header Analyzer  │ │
│  │ LFI    │ │  RFI   │ │ CORS Scanner     │ │
│  │ RCE    │ │  SSRF  │ │ CSRF Auditor     │ │
│  │ CVE*   │ │  TLS   │ │ Brute Force      │ │
│  │ Upload │ │ Redirect│ │ Weak Session     │ │
│  └────────┘ └────────┘ └──────────────────┘ │
│  *CVE: NVD API 2.0 + base local (16 CVEs)   │
└─────────────────┬────────────────────────────┘
                  ▼
┌──────────────────────────────────────────────┐
│  DEDUPLICACIÓN (name + URL + payload)         │
│  Elimina hallazgos exactamente idénticos      │
└─────────────────┬────────────────────────────┘
                  ▼
┌──────────────────────────────────────────────┐
│     ANÁLISIS IA (Llama 3.3 70B via Groq)     │
│   Informe Ejecutivo + Riesgo de Negocio      │
└─────────────────┬────────────────────────────┘
                  ▼
       ┌──────────┴──────────┐
       │  PDF · JSON · CSV   │
       │  SQLite (Historial) │
       └─────────────────────┘
```

### Cobertura OWASP Top 10 (2021)

| # | Categoría OWASP | Módulo(s) | Estado |
|---|----------------|-----------|:------:|
| A01 | Broken Access Control | Open Redirect, CORS Scanner | ✅ |
| A02 | Cryptographic Failures | TLS Checker, Sensitive Data Scanner | ✅ |
| A03 | Injection | SQLi, XSS, Command Injection, LFI, RFI, SSRF* | ✅ |
| A04 | Insecure Design | File Upload Detector | ✅ |
| A05 | Security Misconfiguration | Headers, Dir Listing, HTTP Methods, Exposure, Path Fuzzer | ✅ |
| A06 | Vulnerable Components | CVE Lookup (NVD API), Tech Fingerprinter | ✅ |
| A07 | Auth Failures | CSRF, Brute Force, Weak Session | ✅ |
| A08 | Software & Data Integrity | — | ⬜ No evaluable externamente |
| A09 | Logging & Monitoring | — | ⬜ No evaluable externamente |
| A10 | SSRF | SSRF Scanner | ✅ |

> *\*SSRF se clasifica oficialmente como A10 en OWASP Top 10 (2021), pero se agrupa también en A03 por su naturaleza de inyección server-side.*

---

## 🧪 Tests

VulnSeeker cuenta con **194 pruebas unitarias** organizadas en 34 archivos de test. Todos los módulos están cubiertos con tests que utilizan mocking de respuestas HTTP para garantizar ejecución determinista y sin dependencia de red.

```bash
# Ejecutar la suite completa
pytest tests/ -v

# Resultado esperado
194 passed ✅
```

La integración continua ejecuta la suite completa en cada push vía **GitHub Actions**.

---

## ⚠️ Limitaciones Conocidas

- **Detección heurística:** Los módulos de inyección combinan técnicas *error-based*, detección ciega *time-based* (SQLi y command injection), inyección en cuerpos JSON y un componente compartido de vectores (`injection_points`). No se detectan aún XSS almacenado (*stored*) ni DOM XSS, que requieren seguimiento de estado o ejecución de JavaScript del lado cliente.
- **SSRF in-band:** Detección por análisis de respuesta HTTP; no usa callbacks OOB (Out-of-Band).
- **Subdominios como recon:** Los subdominios descubiertos vía OSINT no se escanean automáticamente (requiere autorización explícita).
- **IA dependiente de API:** El informe ejecutivo requiere conectividad con Groq API; el resto del framework opera offline.
- **SPAs sin spec ni rutas legibles:** El descubrimiento API-aware cubre SPAs que publican OpenAPI/Swagger o referencian sus rutas en el JavaScript; aquellas que ofusquen por completo sus endpoints requerirían un motor de renderizado *headless* (trabajo futuro).
- **Validación en entorno controlado:** 0 falsos positivos observados contra DVWA (low security), con validación adicional contra Altoro Mutual y la SPA OWASP Juice Shop; en producción los resultados pueden variar.
- **Límites cuantificados contra el OWASP Benchmark:** la medición con *ground truth* reveló que VulnSeeker es ciego ante el *path traversal* y el *command injection* sin reflejo, y que no cubre vectores de inyección por cabecera o cuerpo XML (≈34% de los casos). Se incorporaron técnicas ciegas *time-based* (cmdi) y *error-based* (LFI) para esos casos, pero se verificó empíricamente que el banco sintético **no las expone**: no bloquea la respuesta con el retardo del comando (`sleep 10` → ~0.06 s) ni propaga la traza de error de archivo. Su eficacia se materializa en apps reales (DVWA), no en el oráculo. La carencia de XSS por `POST` que la medición destapó sí fue subsanada extendiendo el módulo (Youden XSS 0.38 → 0.87). Son líneas de mejora abordables sin tocar la arquitectura modular.

Para más detalles, consulte la sección de Limitaciones del Estudio en el [documento de tesis](tesis/main.pdf).

---

## 🚀 Instalación

### Requisitos Previos
- Python 3.10+
- pip (gestor de paquetes)
- *(Opcional)* API Key de [Groq](https://console.groq.com/) para el módulo de IA

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/palmar973/VulnSeeker.git
cd VulnSeeker

# 2. Crear entorno virtual
python -m venv .venv

# 3. Activar entorno virtual
# Windows:
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# 4. Instalar dependencias
pip install -r requirements.txt

# 5. (Opcional) Instalar dependencias de desarrollo
pip install -r requirements-dev.txt

# 6. Ejecutar la GUI
python gui.py
```

### Uso por CLI

```bash
# Escaneo simple (URL única)
python main.py -u http://target.com

# Escaneo con Crawler (descubrimiento automático de endpoints)
python main.py -u http://target.com --crawl
```

---

## 🌐 Sobre vulnseeker.software

El sitio web [vulnseeker.software](https://vulnseeker.software) es **exclusivamente una landing page** de presentación y documentación del proyecto. VulnSeeker es una **aplicación de escritorio local** — no existe ni existirá una versión ejecutable desde el navegador.

Esta decisión es deliberada: un escáner de vulnerabilidades requiere acceso directo a la red, ejecución multihilo sin restricciones del navegador y la capacidad de realizar cientos de peticiones HTTP concurrentes con control total sobre headers, timeouts y payloads. La arquitectura local garantiza **máxima potencia de escaneo** y **total control del operador** sobre la herramienta.

---

## 📚 Contexto Académico

VulnSeeker es desarrollado como Trabajo de Grado para la **Licenciatura en Computación** de la **Facultad Experimental de Ciencias, Universidad del Zulia**, Maracaibo, Venezuela.

**Título:** *Escáner Modular para la Detección Automatizada de Vulnerabilidades en Aplicaciones Web*

**Autor:** Claudio Enrique Palmar León · **Tutor:** Prof. Sigerist Rodríguez

---

## ⚠️ Disclaimer Legal

```
VulnSeeker ha sido desarrollado con fines EXCLUSIVAMENTE educativos y de investigación académica.

El uso de esta herramienta contra sistemas sin AUTORIZACIÓN EXPLÍCITA Y POR ESCRITO del propietario
es ILEGAL y puede constituir un delito según las leyes de tu jurisdicción.

El autor no se hace responsable del uso indebido de esta herramienta.
Úsala exclusivamente en entornos controlados, laboratorios de prueba o con autorización formal.
```

---

## 📄 Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE).

Desarrollado por **Claudio Enrique Palmar León** · 2025-2026

---

<div align="center">

*«La seguridad no es un producto, es un proceso.»* — Bruce Schneier

</div>
