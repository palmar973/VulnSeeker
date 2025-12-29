#!/usr/bin/env python3.14
"""
DatabaseManager - FASE 18: Soporte para Reportes PDF.
Agregado: get_scan_date() para la portada del PDF.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from core.config import GlobalConfig
from core.models import Vulnerability, Severity

logger = logging.getLogger("VulnSeeker.DB")


class DatabaseManager:
    """Singleton analítico con soporte granular + settings persistentes."""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self.db_path = Path(GlobalConfig.REPORTS_DIR) / "vulns.db"
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Inicialización idempotente de esquema."""
        self.db_path.parent.mkdir(exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")

            conn.execute("""
                         CREATE TABLE IF NOT EXISTS scans
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             target_url
                             TEXT
                             NOT
                             NULL,
                             scan_date
                             TEXT
                             NOT
                             NULL,
                             total_vulns
                             INTEGER
                             DEFAULT
                             0
                         )
                         """)

            conn.execute("""
                         CREATE TABLE IF NOT EXISTS vulnerabilities
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             scan_id
                             INTEGER
                             NOT
                             NULL,
                             name
                             TEXT
                             NOT
                             NULL,
                             description
                             TEXT,
                             severity
                             INTEGER
                             NOT
                             NULL,
                             target_url
                             TEXT,
                             payload
                             TEXT,
                             FOREIGN
                             KEY
                         (
                             scan_id
                         ) REFERENCES scans
                         (
                             id
                         )
                             )
                         """)

            conn.execute("""
                         CREATE TABLE IF NOT EXISTS settings
                         (
                             key
                             TEXT
                             PRIMARY
                             KEY,
                             value
                             TEXT
                             NOT
                             NULL
                         )
                         """)

            conn.commit()
            logger.info(f"🗄️  DB inicializada: {self.db_path}")

    def save_scan_results(self, target_url: str, vulnerabilities: List[Any]) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")

                conn.execute(
                    "INSERT INTO scans (target_url, scan_date, total_vulns) VALUES (?, ?, ?)",
                    (target_url, datetime.utcnow().isoformat(), len(vulnerabilities))
                )
                scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

                sev_map = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

                for vuln in vulnerabilities:
                    if hasattr(vuln, 'name'):
                        v_name = vuln.name
                        v_desc = vuln.description
                        v_sev = vuln.severity
                        v_target = getattr(vuln, 'target_url', target_url)
                        v_payload = getattr(vuln, 'payload', '')
                    else:
                        v_name = vuln.get('name', 'Unknown')
                        v_desc = vuln.get('description', '')
                        v_sev = vuln.get('severity', 'LOW')
                        v_target = vuln.get('target_url', target_url)
                        v_payload = vuln.get('payload', '')

                    if hasattr(v_sev, 'value'):
                        sev_str = v_sev.value.upper()
                    else:
                        sev_str = str(v_sev).upper()

                    sev_int = sev_map.get(sev_str, 1)

                    conn.execute("""
                                 INSERT INTO vulnerabilities
                                     (scan_id, name, description, severity, target_url, payload)
                                 VALUES (?, ?, ?, ?, ?, ?)
                                 """, (scan_id, v_name, v_desc, sev_int, v_target, v_payload))

                conn.commit()
                logger.info(f"💾 Scan {scan_id} guardado exitosamente ({len(vulnerabilities)} hallazgos).")
                return scan_id

        except Exception as e:
            logger.error(f"❌ Error CRÍTICO guardando en DB: {e}")
            raise

    # --- MÉTODOS DE CONFIGURACIÓN ---
    def save_api_key(self, api_key: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("groq_api_key", api_key)
                )
                conn.commit()
                logger.info("🔑 Groq API Key guardada persistentemente")
        except Exception as e:
            logger.error(f"❌ Error guardando API Key: {e}")
            raise

    def get_api_key(self) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                result = conn.execute(
                    "SELECT value FROM settings WHERE key = ?",
                    ("groq_api_key",)
                ).fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"❌ Error recuperando API Key: {e}")
            return None

    # --- MÉTODOS DE LECTURA ---
    def get_all_scans(self) -> List[Tuple[int, str, str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute("""
                                    SELECT s.id, s.scan_date, s.target_url, s.total_vulns
                                    FROM scans s
                                    ORDER BY s.scan_date DESC
                                    """).fetchall()
        except Exception as e:
            logger.error(f"Error fetching scans: {e}")
            return []

    def get_unique_targets(self) -> List[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return [row[0] for row in conn.execute("""
                                                       SELECT DISTINCT target_url
                                                       FROM scans
                                                       ORDER BY target_url
                                                       """).fetchall()]
        except Exception as e:
            logger.error(f"Error fetching unique targets: {e}")
            return []

    def get_scans_by_target(self, target_url: str) -> List[Tuple[int, str, str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute("""
                                    SELECT s.id, s.scan_date, s.target_url, s.total_vulns
                                    FROM scans s
                                    WHERE s.target_url = ?
                                    ORDER BY s.scan_date DESC
                                    """, (target_url,)).fetchall()
        except Exception as e:
            logger.error(f"Error fetching scans by target: {e}")
            return []

    def get_scan_stats(self, scan_id: int) -> Dict[str, int]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                total_vulns = conn.execute(
                    "SELECT total_vulns FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()[0] or 0

                critical_high = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity >= 3", (scan_id,)
                ).fetchone()[0]

                # Para el PDF
                medium_low = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity < 3", (scan_id,)
                ).fetchone()[0]

                return {
                    "total_vulns": total_vulns,
                    "critical_high": critical_high,
                    "medium_low": medium_low
                }
        except Exception as e:
            logger.error(f"Error fetching scan stats: {e}")
            return {"total_vulns": 0, "critical_high": 0, "medium_low": 0}

    def get_scan_target(self, scan_id: int) -> str:
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT target_url FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return res[0] if res else "Unknown Target"
        except Exception as e:
            logger.error(f"Error fetching target: {e}")
            return "Error"

    # FASE 18: MÉTODO FALTANTE PARA PDF
    def get_scan_date(self, scan_id: int) -> str:
        """Recupera la fecha del scan para el reporte."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT scan_date FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if res:
                    try:
                        # Formato amigable: "29-12-2025 14:30"
                        dt = datetime.fromisoformat(res[0].replace('Z', '+00:00'))
                        return dt.strftime("%d-%m-%Y %H:%M:%S")
                    except:
                        return res[0]
                return "Fecha Desconocida"
        except Exception as e:
            logger.error(f"Error fetching scan date: {e}")
            return "Error"

    def get_severity_distribution_by_scan(self, scan_id: int) -> List[Tuple[str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                sev_names = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                result = []
                for idx, name in enumerate(sev_names):
                    count = conn.execute(
                        "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = ?",
                        (scan_id, idx)
                    ).fetchone()[0]
                    if count > 0:
                        result.append((name, count))
                return result
        except Exception as e:
            logger.error(f"Error severity distribution by scan: {e}")
            return []

    def get_top_vulns_by_scan(self, scan_id: int, limit: int = 5) -> List[Tuple[str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute("""
                                    SELECT name, COUNT(*) as count
                                    FROM vulnerabilities
                                    WHERE scan_id = ?
                                    GROUP BY name
                                    ORDER BY count DESC LIMIT ?
                                    """, (scan_id, limit)).fetchall()
        except Exception as e:
            logger.error(f"Error top vulns by scan: {e}")
            return []

    def get_vulnerabilities_by_scan(self, scan_id: int) -> List[Any]:
        """Retorna objetos con atributos 'vuln_type' mapeado a 'name' para el PDF."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("""
                                    SELECT name, description, severity, target_url, payload
                                    FROM vulnerabilities
                                    WHERE scan_id = ?
                                    """, (scan_id,)).fetchall()

                int_to_sev = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

                # Clase simple para el PDF generator (Duck Typing)
                class PDFVuln:
                    def __init__(self, name, desc, sev_int, url, payload):
                        self.vuln_type = name  # Mapeo para que el PDF lo lea
                        self.name = name
                        self.description = desc
                        self.severity = int_to_sev.get(sev_int, "INFO")
                        self.url = url
                        self.payload = payload

                return [PDFVuln(*r) for r in rows]

        except Exception as e:
            logger.error(f"Error fetching vulns for PDF: {e}")
            return []