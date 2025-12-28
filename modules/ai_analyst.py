#!/usr/bin/env python3.14
"""
GroqAIAnalyst - FASE 14 FIX: Type Comparison Error.
Llama 3.3 70B como CISO Ejecutivo.
"""

from groq import Groq
from typing import List, Dict, Any, Optional
from core.models import Vulnerability, Severity
import json
import logging
from datetime import datetime

logger = logging.getLogger("VulnSeeker")


class GroqAIAnalyst:
    """Analista IA con Llama 3.3 70B - Traduce tecnicismos a riesgos de negocio."""

    SYSTEM_PROMPT = """Eres un CISO (Chief Information Security Officer) con 20 años de experiencia.
Tu trabajo es analizar reportes técnicos de vulnerabilidades web y traducirlos a 
riesgos de negocio ejecutivos. Habla en ESPAÑOL corporativo, directo y preciso.

ESTRUCTURA OBLIGATORIA del Informe Ejecutivo:
1. **NIVEL DE RIESGO GLOBAL** (CRÍTICO/ALTO/MEDIO/BAJO) + justificación breve
2. **TOP 3 AMENZAS CRÍTICAS** - Impacto en negocio + ejemplos concretos
3. **PLAN DE ACCIÓN INMEDIATO** - 5 bullets prioritarios (48h)
4. **RECOMENDACIONES ESTRATÉGICAS** - Mediano plazo (1 mes)

Sé específico con números. Usa lenguaje de directiva (ROI, multas GDPR, reputación).
"""

    def __init__(self):
        self.model = "llama-3.3-70b-versatile"
        # Mapeo para convertir Enums a Enteros y poder comparar
        self.SEVERITY_WEIGHTS = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }

    def _generate_stats_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Token optimization: Resume vulns a estadísticas."""
        if not vulnerabilities:
            return {"total": 0, "risk_score": 0, "message": "Sin vulnerabilidades detectadas"}

        stats = {
            "total": len(vulnerabilities),
            "by_severity": {},
            "by_module": {},
            "critical_files": [],
            "open_ports": [],
            "risk_score": 0
        }

        critical_keywords = [".env", ".git", "backup.sql", "config.php", "admin/", "shadow"]

        for vuln in vulnerabilities:
            # 1. Severidad (Nombre para el reporte)
            sev_name = vuln.severity.name if hasattr(vuln.severity, 'name') else str(vuln.severity)
            stats["by_severity"][sev_name] = stats["by_severity"].get(sev_name, 0) + 1

            # 2. Módulo
            module_name = vuln.name.split(":")[0] if ":" in vuln.name else "Unknown"
            stats["by_module"][module_name] = stats["by_module"].get(module_name, 0) + 1

            # 3. Comparación numérica segura (FIX PRINCIPAL)
            # Convertimos el Enum a entero usando el diccionario
            vuln_weight = self.SEVERITY_WEIGHTS.get(vuln.severity, 0)

            # Ahora sí podemos comparar con >= 3
            if vuln_weight >= 3:  # HIGH o CRITICAL
                # Buscar archivos sensibles
                if any(keyword in vuln.name.lower() for keyword in critical_keywords):
                    stats["critical_files"].append({
                        "name": vuln.name,
                        "url": vuln.target_url,
                        "impact": "Exposición de información sensible"
                    })

            # Open ports
            if "PortScanner" in vuln.name:
                stats["open_ports"].append(vuln.name.split()[-1])

        # Risk score calculation
        crit_count = stats["by_severity"].get("CRITICAL", 0)
        high_count = stats["by_severity"].get("HIGH", 0)
        stats["risk_score"] = min(100, (crit_count * 20) + (high_count * 5))

        return stats

    def generate_security_report(self, api_key: str, vulnerabilities: List[Vulnerability], target_url: str = "") -> str:
        """
        Genera informe ejecutivo con Llama 3.3 70B.
        """
        # Inicializar stats vacío por si falla la generación (Evita UnboundLocalError)
        stats = {"total": 0, "risk_score": 0, "by_severity": {}}

        try:
            # 1. Generar resumen estadístico
            stats = self._generate_stats_summary(vulnerabilities)

            # 2. Construir prompt
            summary_text = self._build_summary_prompt(stats, target_url)

            # 3. Llamada a Groq
            client = Groq(api_key=api_key)

            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": summary_text}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=1500,
                stream=False
            )

            report = chat_completion.choices[0].message.content.strip()
            logger.info("🤖 Llama 3.3 70B: Informe generado.")
            return report

        except Exception as e:
            error_msg = f"❌ Error Groq API: {str(e)}"
            logger.error(error_msg)

            # Fallback seguro
            return f"""
**ERROR DE CONEXIÓN CON IA**
{str(e)}

**RESUMEN TÉCNICO DE CONTINGENCIA:**
- Objetivo: {target_url}
- Total Hallazgos: {stats.get('total', 'N/A')}
- Puntuación de Riesgo: {stats.get('risk_score', 0)}/100

Verifique su conexión a Internet y que la API Key de Groq sea válida.
            """

    def _build_summary_prompt(self, stats: Dict[str, Any], target_url: str) -> str:
        sev_summary = ", ".join([f"{k}: {v}" for k, v in stats["by_severity"].items()])
        mod_summary = ", ".join([f"{k}: {v}" for k, v in list(stats["by_module"].items())[:5]])

        critical_files = "\n".join([f"- {f['name']} ({f['url']})" for f in stats["critical_files"][:5]])
        ports = ", ".join(stats["open_ports"][:5]) if stats["open_ports"] else "Ninguno"

        return f"""
DATOS DEL ESCANEO:
Target: {target_url}
Fecha: {datetime.now().strftime("%Y-%m-%d")}
Total Vulns: {stats["total"]}
Risk Score: {stats["risk_score"]}/100

Distribución: {sev_summary}
Módulos: {mod_summary}

Archivos Críticos Expuestos:
{critical_files if critical_files else "Ninguno detectado"}

Puertos Abiertos: {ports}

Instrucción: Analiza estos datos y genera el Informe Ejecutivo CISO.
"""