#!/usr/bin/env python3.14
"""
DatabaseManager - FASE 11.1 + BUGFIX FINAL.
Implementación "Duck Typing" para evitar conflictos de importación.
Maneja objetos y diccionarios indiscriminadamente.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from core.config import GlobalConfig

# Ya no necesitamos importar el modelo para validar tipos.
# Usaremos detección dinámica de atributos.

logger = logging.getLogger("VulnSeeker.DB")


class DatabaseManager:
    """Singleton analítico para KPIs, distribuciones y top vulnerabilidades."""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            # Usar GlobalConfig para la ruta correcta
            self.db_path = Path(GlobalConfig.REPORTS_DIR) / "vulns.db"
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Inicialización idempotente de esquema."""
        self.db_path.parent.mkdir(exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")

            # Tabla scans (padre)
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

            # Tabla vulnerabilities (hija)
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

            conn.commit()
            logger.info(f"🗄️  DB inicializada: {self.db_path}")

    def save_scan_results(self, target_url: str, vulnerabilities: List[Any]) -> int:
        """
        Método BLINDADO (Bulletproof).
        Usa 'hasattr' para detectar si es objeto o dict. No falla por imports cruzados.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")

                # Insert scan
                conn.execute(
                    "INSERT INTO scans (target_url, scan_date, total_vulns) VALUES (?, ?, ?)",
                    (target_url, datetime.utcnow().isoformat(), len(vulnerabilities))
                )
                scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

                # Mapeo de severidad
                sev_map = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

                for vuln in vulnerabilities:
                    # 1. EXTRACCIÓN DE DATOS (DUCK TYPING)
                    if hasattr(vuln, 'name'):
                        # Es un objeto (Vulnerability o similar)
                        v_name = vuln.name
                        v_desc = vuln.description
                        v_sev = vuln.severity
                        v_target = getattr(vuln, 'target_url', target_url)
                        v_payload = getattr(vuln, 'payload', '')
                    else:
                        # Es un diccionario
                        v_name = vuln.get('name', 'Unknown')
                        v_desc = vuln.get('description', '')
                        v_sev = vuln.get('severity', 'LOW')
                        v_target = vuln.get('target_url', target_url)
                        v_payload = vuln.get('payload', '')

                    # 2. NORMALIZACIÓN DE SEVERIDAD
                    # Maneja Enum, String o Int
                    if hasattr(v_sev, 'value'):  # Es un Enum
                        sev_str = v_sev.value.upper()
                    else:
                        sev_str = str(v_sev).upper()

                    sev_int = sev_map.get(sev_str, 1)  # Default 1 (LOW)

                    # 3. INSERTAR
                    conn.execute("""
                                 INSERT INTO vulnerabilities
                                     (scan_id, name, description, severity, target_url, payload)
                                 VALUES (?, ?, ?, ?, ?, ?)
                                 """, (
                                     scan_id, v_name, v_desc, sev_int,
                                     v_target, v_payload
                                 ))

                conn.commit()
                logger.info(f"💾 Scan {scan_id} guardado exitosamente ({len(vulnerabilities)} hallazgos).")
                return scan_id

        except Exception as e:
            logger.error(f"❌ Error CRÍTICO guardando en DB: {e}")
            raise

    def get_all_scans(self) -> List[Tuple[int, str, str, int]]:
        """Historial completo para UI."""
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

    def get_kpis(self) -> Dict[str, int]:
        """KPIs ejecutivos para Dashboard."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                total_vulns = conn.execute("SELECT COALESCE(SUM(total_vulns), 0) FROM scans").fetchone()[0]
                critical_high = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity >= 3").fetchone()[0]

                return {
                    "total_scans": total_scans,
                    "total_vulns": total_vulns,
                    "critical_high": critical_high
                }
        except Exception as e:
            logger.error(f"Error fetching KPIs: {e}")
            return {"total_scans": 0, "total_vulns": 0, "critical_high": 0}

    def get_severity_distribution(self) -> List[Tuple[str, int]]:
        """Pie Chart data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                sev_names = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                result = []
                for idx, name in enumerate(sev_names):
                    count = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = ?", (idx,)).fetchone()[
                        0]
                    if count > 0:
                        result.append((name, count))
                return result
        except Exception as e:
            logger.error(f"Error severity distribution: {e}")
            return []

    def get_top_vulnerabilities(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Bar Chart data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute("""
                                    SELECT name, COUNT(*) as count
                                    FROM vulnerabilities
                                    GROUP BY name
                                    ORDER BY count DESC LIMIT ?
                                    """, (limit,)).fetchall()
        except Exception as e:
            logger.error(f"Error top vulnerabilities: {e}")
            return []