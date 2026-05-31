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

**Escáner Modular de Vulnerabilidades Web · Enterprise Edition**

[![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-113%20passing-brightgreen?logo=pytest&logoColor=white)]()
[![Modules](https://img.shields.io/badge/Modules-26%20scanners-orange?logo=shield&logoColor=white)]()
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-8%2F10-red?logo=owasp&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![AI](https://img.shields.io/badge/AI-Llama%203.3%2070B-purple?logo=meta)](https://groq.com/)
[![NVD](https://img.shields.io/badge/NVD-API%202.0-yellow?logo=nist&logoColor=white)](https://nvd.nist.gov/)

</div>

---

## 🔍 ¿Qué es VulnSeeker?

**VulnSeeker Enterprise** es un framework DAST (Dynamic Application Security Testing) avanzado, desarrollado en Python, diseñado para realizar auditorías de seguridad automatizadas de forma integral. A diferencia de escáneres básicos que se limitan a un solo vector de ataque, VulnSeeker orquesta **26 módulos independientes** de análisis — desde inyecciones SQL y XSS hasta reconocimiento OSINT de subdominios, consulta de CVEs en tiempo real contra la NVD del NIST, y análisis con Inteligencia Artificial.

El sistema opera bajo una arquitectura modular extensible donde cada módulo hereda de la clase base `ScannerModule` y se registra en el motor central, permitiendo agregar nuevas capacidades de escaneo sin modificar el núcleo del sistema.

### ¿Por qué VulnSeeker?

- **Cobertura real.** No es un script que lanza payloads a ciegas. VulnSeeker ejecuta una cadena completa: reconocimiento → fingerprinting → crawling → ataque multihilo → análisis IA → reporte.
- **8/10 categorías del OWASP Top 10 (2021).** Las 2 restantes (A08, A09) no son evaluables externamente mediante DAST.
- **Inteligencia Artificial integrada.** Llama 3.3 70B actúa como un CISO virtual que traduce hallazgos técnicos en riesgos de negocio ejecutivos.
- **CVEs en tiempo real.** Integración con la API 2.0 del NIST NVD para consultar vulnerabilidades conocidas asociadas a las tecnologías detectadas.
- **108 tests unitarios.** Suite completa con `pytest` y pipeline CI/CD en GitHub Actions.
- **Persistencia histórica.** Cada escaneo se almacena en SQLite, permitiendo análisis de tendencias y comparación entre auditorías.

---

## ⚡ Módulos de Detección

### Inyección y Ejecución (A03 — Injection)

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **SQL Injection** | Detección de SQLi basada en errores (MySQL, PostgreSQL, Oracle, MSSQL) | 🔴 CRITICAL |
| **Cross-Site Scripting** | Identificación de XSS reflejado mediante inyección de canarios | 🟠 HIGH |
| **Command Injection** | Detección de ejecución remota de comandos (RCE) en parámetros | 🔴 CRITICAL |
| **Local File Inclusion** | Pruebas de traversal de directorios para lectura de archivos locales | 🔴 HIGH |
| **Remote File Inclusion** | Detección de inclusión de archivos remotos en aplicaciones web | 🔴 HIGH |
| **SSRF Scanner** | Detección de Server-Side Request Forgery mediante callbacks | 🔴 HIGH |

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
| **Tech Fingerprinter** | Identificación de servidor, lenguaje backend, CMS/Framework y versiones |
| **Subdomain Scanner** | Descubrimiento pasivo OSINT vía crt.sh y HackerTarget con validación de subdominios live |
| **Port Scanner** | Escaneo de puertos TCP abiertos con identificación de servicios |

### Inteligencia Artificial

| Característica | Detalle |
|---------------|---------|
| **Modelo** | Llama 3.3 70B vía Groq API |
| **Función** | Generación de informes ejecutivos CISO con análisis de riesgo de negocio |
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
│   ├── fingerprinter.py          # Fingerprinting tecnológico (Server/CMS/Backend)
│   ├── subdomain_scanner.py      # OSINT de subdominios (crt.sh + HackerTarget)
│   └── db_manager.py             # Persistencia SQLite (Singleton)
│
├── modules/                      # 26 módulos de escaneo independientes
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
│   ├── tech_visualizer.py        # Architecture Map Generator
│   └── ai_analyst.py             # AI Analyst (Groq / Llama 3.3 70B)
│
├── ui/                           # Interfaz gráfica
│   └── main_window.py            # GUI completa (CustomTkinter + Matplotlib)
│
├── reports/                      # Sistema de reportes
│   ├── report_generator.py       # Exportador JSON/CSV
│   └── pdf_generator.py          # Generador PDF (ReportLab + gráficos)
│
├── tests/                        # 108 tests unitarios (pytest)
│   ├── test_sqli.py
│   ├── test_xss.py
│   ├── test_cmd_injection.py
│   ├── test_cve_lookup.py
│   ├── ...                       # 22 archivos de test
│   └── test_weak_session.py
│
├── .github/workflows/ci.yml     # CI/CD Pipeline (GitHub Actions)
├── main.py                      # Punto de entrada CLI
├── gui.py                       # Punto de entrada GUI
└── requirements.txt             # Dependencias del proyecto
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
│     ATAQUE MULTIHILO (26 módulos en paralelo)│
│  ┌────────┐ ┌────────┐ ┌──────────────────┐ │
│  │ SQLi   │ │  XSS   │ │ Header Analyzer  │ │
│  │ LFI    │ │  RFI   │ │ CORS Scanner     │ │
│  │ RCE    │ │  SSRF  │ │ CSRF Auditor     │ │
│  │ CVE    │ │  TLS   │ │ Brute Force      │ │
│  │ Upload │ │ Redirect│ │ Weak Session     │ │
│  └────────┘ └────────┘ └──────────────────┘ │
└─────────────────┬────────────────────────────┘
                  ▼
┌──────────────────────────────────────────────┐
│      CVE LOOKUP (NVD API 2.0 en vivo)        │
│   Base local (16 CVEs) + consulta al NIST    │
└─────────────────┬────────────────────────────┘
                  ▼
┌──────────────────────────────────────────────┐
│     ANÁLISIS IA (Llama 3.3 70B via Groq)     │
│   Informe CISO + Riesgo de Negocio           │
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
| A03 | Injection | SQLi, XSS, Command Injection, LFI, RFI | ✅ |
| A04 | Insecure Design | File Upload Detector | ✅ |
| A05 | Security Misconfiguration | Headers, Dir Listing, HTTP Methods, Exposure, Path Fuzzer | ✅ |
| A06 | Vulnerable Components | CVE Lookup (NVD API), Tech Fingerprinter | ✅ |
| A07 | Auth Failures | CSRF, Brute Force, Weak Session | ✅ |
| A08 | Software & Data Integrity | — | ⬜ No evaluable externamente |
| A09 | Logging & Monitoring | — | ⬜ No evaluable externamente |
| A10 | SSRF | SSRF Scanner | ✅ |

---

## 🧪 Tests

VulnSeeker cuenta con **108 pruebas unitarias** organizadas en 22 archivos de test. Todos los módulos están cubiertos con tests que utilizan mocking de respuestas HTTP para garantizar ejecución determinista y sin dependencia de red.

```bash
# Ejecutar la suite completa
pytest tests/ -v

# Resultado esperado
108 passed ✅
```

La integración continua ejecuta la suite completa en cada push vía **GitHub Actions**.

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

# 5. Ejecutar la GUI
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
