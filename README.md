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
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![AI](https://img.shields.io/badge/AI-Llama%203.3%2070B-purple?logo=meta)](https://groq.com/)

</div>

---

## 🔍 ¿Qué es VulnSeeker?

**VulnSeeker Enterprise** es un escáner de vulnerabilidades web avanzado, desarrollado en Python, diseñado para realizar auditorías de seguridad automatizadas de forma integral. A diferencia de escáneres básicos que se limitan a un solo vector de ataque, VulnSeeker orquesta **16 módulos independientes** de análisis en paralelo — desde inyecciones SQL y XSS hasta reconocimiento OSINT de subdominios y análisis con Inteligencia Artificial.

El sistema opera bajo una arquitectura modular extensible donde cada módulo es un componente independiente que se registra en el motor central, permitiendo agregar nuevas capacidades de escaneo sin modificar el núcleo del sistema.

### ¿Por qué VulnSeeker?

- **Cobertura real.** No es un script que lanza payloads a ciegas. VulnSeeker ejecuta una cadena completa: reconocimiento → fingerprinting → crawling → ataque multihilo → análisis IA → reporte.
- **Inteligencia Artificial integrada.** Llama 3.3 70B actúa como un CISO virtual que traduce hallazgos técnicos en riesgos de negocio ejecutivos.
- **Persistencia histórica.** Cada escaneo se almacena en SQLite, permitiendo análisis de tendencias y comparación entre auditorías.

---

## ⚡ Características Principales

### Módulos de Ataque

| Módulo | Descripción | Severidad |
|--------|-------------|-----------|
| **SQL Injection** | Detección de SQLi basada en errores (MySQL, PostgreSQL, Oracle, MSSQL) | 🔴 HIGH |
| **Cross-Site Scripting** | Identificación de XSS reflejado mediante inyección de canarios | 🟠 MEDIUM |
| **Command Injection** | Detección de ejecución remota de comandos (RCE) en parámetros | 🔴 CRITICAL |
| **Local File Inclusion** | Pruebas de traversal de directorios para lectura de archivos locales | 🔴 HIGH |
| **Remote File Inclusion** | Detección de inclusión de archivos remotos en aplicaciones web | 🔴 HIGH |

### Módulos de Reconocimiento y Análisis

| Módulo | Descripción |
|--------|-------------|
| **Web Crawler** | Explorador estructural que mapea URLs, formularios y puntos de entrada |
| **Tech Fingerprinter** | Identificación de servidor, lenguaje backend y CMS/Framework |
| **Subdomain Scanner** | Descubrimiento pasivo OSINT vía crt.sh y HackerTarget con validación de subdominios live |
| **Port Scanner** | Escaneo de puertos abiertos en el objetivo |
| **Path Fuzzer** | Descubrimiento de rutas y archivos ocultos mediante diccionarios |

### Módulos de Configuración y Hardening

| Módulo | Descripción |
|--------|-------------|
| **Header Analyzer** | Evaluación de cabeceras de seguridad (CSP, HSTS, X-Frame-Options, etc.) |
| **Cookie Scanner** | Auditoría de atributos de cookies (Secure, HttpOnly, SameSite) |
| **WAF Detector** | Identificación de Web Application Firewalls activos |
| **CMS Auditor** | Análisis específico para WordPress, Joomla, Drupal y otros CMS |
| **Exposure Scanner** | Detección de archivos sensibles expuestos (.env, .git, backups, configs) |

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
├── core/                    # Núcleo del sistema
│   ├── engine.py            # Orquestador principal (multihilo)
│   ├── scanner_types.py     # Tipos base: Target, Vulnerability, ScannerModule
│   ├── models.py            # Estructuras de datos compartidas
│   ├── config.py            # Configuración global centralizada
│   ├── crawler.py           # Web Crawler estructural
│   ├── fingerprinter.py     # Detective tecnológico (Server/CMS/Backend)
│   ├── subdomain_scanner.py # Conquistador OSINT (crt.sh + HackerTarget)
│   └── db_manager.py        # Persistencia SQLite (Singleton)
│
├── modules/                 # Módulos de escaneo independientes
│   ├── sqli_module.py       # SQL Injection (Error-Based)
│   ├── xss_module.py        # Reflected XSS
│   ├── cmd_injection.py     # Command Injection / RCE
│   ├── lfi_scanner.py       # Local File Inclusion
│   ├── rfi_scanner.py       # Remote File Inclusion
│   ├── header_analyzer.py   # Análisis de cabeceras HTTP
│   ├── cookie_scanner.py    # Auditoría de cookies
│   ├── waf_detector.py      # Detección de WAF
│   ├── cms_auditor.py       # Auditoría de CMS
│   ├── exposure_scanner.py  # Archivos sensibles expuestos
│   ├── port_scanner.py      # Escaneo de puertos
│   ├── path_fuzzer.py       # Fuzzing de rutas
│   ├── email_harvester.py   # Recolección de correos electrónicos
│   ├── tech_visualizer.py   # Visualización de arquitectura tecnológica
│   └── ai_analyst.py        # Analista IA (Groq / Llama 3.3 70B)
│
├── ui/                      # Interfaz gráfica
│   └── main_window.py       # GUI completa (CustomTkinter + Matplotlib)
│
├── reports/                 # Sistema de reportes
│   ├── report_generator.py  # Exportador JSON
│   └── pdf_generator.py     # Generador PDF (ReportLab + gráficos)
│
├── main.py                  # Punto de entrada CLI
├── gui.py                   # Punto de entrada GUI
└── requirements.txt         # Dependencias del proyecto
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
│    Web Crawler   │ ← URLs + Formularios + Parámetros
└────────┬────────┘
         ▼
┌─────────────────────────────────────┐
│     ATAQUE MULTIHILO (10 hilos)     │
│  ┌───────┐ ┌───────┐ ┌───────────┐ │
│  │ SQLi  │ │  XSS  │ │ Headers   │ │
│  │ LFI   │ │  RFI  │ │ Cookies   │ │
│  │ RCE   │ │  WAF  │ │ Exposure  │ │
│  └───────┘ └───────┘ └───────────┘ │
└────────────────┬────────────────────┘
                 ▼
┌─────────────────────────────────────┐
│   ANÁLISIS IA (Llama 3.3 70B)      │
│   Informe CISO + Riesgo de Negocio │
└────────────────┬────────────────────┘
                 ▼
      ┌──────────┴──────────┐
      │   PDF · JSON · CSV  │
      │   SQLite (Historial)│
      └─────────────────────┘
```

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

Desarrollado por **Claudio Enrique Palmar León** · 2025

---

<div align="center">

*«La seguridad no es un producto, es un proceso.»* — Bruce Schneier

</div>
