#!/usr/bin/env python3.14
"""
DatabaseManager - FASE 15: Scanner-First UX.
Métodos granulares para vistas contextuales por scan/target.
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
    """Singleton analítico con soporte granular para UX contextual."""

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

            conn.commit()
            logger.info(f"🗄️  DB inicializada: {self.db_path}")

    def save_scan_results(self, target_url: str, vulnerabilities: List[Any]) -> int:
        """Método BLINDADO (Bulletproof - Duck Typing)."""
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

    # FASE 15: NUEVOS MÉTODOS GRANULARES
    def get_unique_targets(self) -> List[str]:
        """Targets únicos para filtro de historial."""
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
        """Escaneos filtrados por target específico."""
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
        """KPIs específicos de UN SOLO scan."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                total_vulns = conn.execute(
                    "SELECT total_vulns FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()[0] or 0

                critical_high = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity >= 3", (scan_id,)
                ).fetchone()[0]

                return {
                    "total_vulns": total_vulns,
                    "critical_high": critical_high
                }
        except Exception as e:
            logger.error(f"Error fetching scan stats: {e}")
            return {"total_vulns": 0, "critical_high": 0}

    def get_severity_distribution_by_scan(self, scan_id: int) -> List[Tuple[str, int]]:
        """Pie Chart data para UN scan específico."""
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
        """Bar Chart data para UN scan específico."""
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

    # MÉTODOS GLOBALES (LEGACY - para compatibilidad)
    def get_kpis(self) -> Dict[str, int]:
        """KPIs ejecutivos para Dashboard (global)."""
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
        """Pie Chart data (global)."""
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
        """Bar Chart data (global)."""
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

    def get_scan_target(self, scan_id: int) -> str:
        """Recupera la URL objetivo de un scan específico."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT target_url FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return res[0] if res else "Unknown Target"
        except Exception as e:
            logger.error(f"Error fetching target: {e}")
            return "Error"

    def get_vulnerabilities_by_scan(self, scan_id: int) -> List[Vulnerability]:
        """Recupera todas las vulnerabilidades de un scan."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("""
                                    SELECT name, description, severity, target_url, payload
                                    FROM vulnerabilities
                                    WHERE scan_id = ?
                                    """, (scan_id,)).fetchall()

                int_to_sev = {
                    0: Severity.INFO,
                    1: Severity.LOW,
                    2: Severity.MEDIUM,
                    3: Severity.HIGH,
                    4: Severity.CRITICAL
                }

                vuln_objects = []
                for r in rows:
                    name, desc, sev_int, url, payload = r
                    vuln_objects.append(Vulnerability(
                        name=name,
                        description=desc,
                        severity=int_to_sev.get(sev_int, Severity.LOW),
                        target_url=url,
                        payload=payload
                    ))

                return vuln_objects

        except Exception as e:
            logger.error(f"Error fetching vulns for AI: {e}")
            return []