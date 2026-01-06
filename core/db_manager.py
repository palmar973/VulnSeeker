#!/usr/bin/env python3.14
"""
DatabaseManager - FASE 20: Soporte para Subdomain Scanner.
🆕 Nueva tabla 'subdomains' + método save_subdomains().
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from core.config import GlobalConfig

logger = logging.getLogger("VulnSeeker.DB")


class DatabaseManager:
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
        """Inicialización + migraciones automáticas."""
        self.db_path.parent.mkdir(exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")

            # Tabla SCANS (con technologies de Fase 19)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    total_vulns INTEGER DEFAULT 0,
                    technologies TEXT DEFAULT 'Unknown'
                )
            """)

            # 🆕 FASE 20: Tabla SUBDOMAINS
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    subdomain TEXT NOT NULL,
                    status TEXT DEFAULT 'LIVE',
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)

            # Tabla VULNERABILITIES
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    severity INTEGER NOT NULL,
                    target_url TEXT,
                    payload TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)

            # Tabla SETTINGS
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            # Migraciones automáticas seguras
            try:
                conn.execute("ALTER TABLE scans ADD COLUMN technologies TEXT DEFAULT 'Unknown'")
            except sqlite3.OperationalError:
                pass  # Ya existe

            conn.commit()
            logger.info("🗄️ DB inicializada/migrada correctamente.")

    # 🆕 FASE 20: MÉTODOS SUBDOMAINS
    def save_subdomains(self, scan_id: int, subdomains: List[str]) -> None:
        """Guarda subdominios encontrados vinculados al scan."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")
                for subdomain in subdomains:
                    conn.execute(
                        "INSERT INTO subdomains (scan_id, subdomain, status) VALUES (?, ?, ?)",
                        (scan_id, subdomain, 'LIVE')
                    )
                conn.commit()
                logger.info(f"💾 {len(subdomains)} subdominios guardados para scan {scan_id}")
        except Exception as e:
            logger.error(f"❌ Error guardando subdominios: {e}")

    def get_subdomain_count(self, scan_id: int) -> int:
        """Retorna cantidad de subdominios para un scan."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute(
                    "SELECT COUNT(*) FROM subdomains WHERE scan_id = ?", (scan_id,)
                ).fetchone()
                return res[0] if res else 0
        except Exception:
            return 0

    def get_subdomains_by_scan(self, scan_id: int) -> List[str]:
        """Lista completa de subdominios de un scan."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                return [row[0] for row in conn.execute(
                    "SELECT subdomain FROM subdomains WHERE scan_id = ?", (scan_id,)
                ).fetchall()]
        except Exception:
            return []

    def save_scan_results(self, target_url: str, vulnerabilities: List[Any],
                         technologies: str = "Unknown") -> int:
        """Guarda resultados incluyendo tecnologías (Fase 19)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")
                conn.execute(
                    "INSERT INTO scans (target_url, scan_date, total_vulns, technologies) "
                    "VALUES (?, ?, ?, ?)",
                    (target_url, datetime.utcnow().isoformat(), len(vulnerabilities), technologies)
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
                logger.info(f"💾 Scan {scan_id} guardado. Tech: {technologies}")
                return scan_id
        except Exception as e:
            logger.error(f"❌ Error CRÍTICO guardando en DB: {e}")
            raise

    # Métodos existentes (sin cambios)
    def get_scan_technologies(self, scan_id: int) -> str:
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT technologies FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return res[0] if res and res[0] else "Análisis no disponible"
        except Exception:
            return "Desconocido"

    def save_api_key(self, api_key: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                           ("groq_api_key", api_key))
                conn.commit()
        except Exception:
            pass

    def get_api_key(self) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT value FROM settings WHERE key = ?", ("groq_api_key",)).fetchone()
                return res[0] if res else None
        except Exception:
            return None

    def get_all_scans(self) -> List[Tuple[int, str, str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute(
                    "SELECT s.id, s.scan_date, s.target_url, s.total_vulns FROM scans s ORDER BY s.scan_date DESC"
                ).fetchall()
        except Exception:
            return []

    def get_unique_targets(self) -> List[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return [row[0] for row in
                        conn.execute("SELECT DISTINCT target_url FROM scans ORDER BY target_url").fetchall()]
        except Exception:
            return []

    def get_scans_by_target(self, target_url: str) -> List[Tuple[int, str, str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute(
                    "SELECT s.id, s.scan_date, s.target_url, s.total_vulns FROM scans s WHERE s.target_url = ? "
                    "ORDER BY s.scan_date DESC", (target_url,)
                ).fetchall()
        except Exception:
            return []

    def get_scan_stats(self, scan_id: int) -> Dict[str, int]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT total_vulns FROM scans WHERE id = ?", (scan_id,)).fetchone()
                crit_high = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity >= 3", (scan_id,)
                ).fetchone()
                med_low = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity < 3", (scan_id,)
                ).fetchone()
                return {
                    "total_vulns": total[0] if total else 0,
                    "critical_high": crit_high[0] if crit_high else 0,
                    "medium_low": med_low[0] if med_low else 0
                }
        except Exception:
            return {"total_vulns": 0, "critical_high": 0, "medium_low": 0}

    def get_scan_target(self, scan_id: int) -> str:
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT target_url FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return res[0] if res else "Unknown"
        except Exception:
            return "Error"

    def get_scan_date(self, scan_id: int) -> str:
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT scan_date FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if res:
                    try:
                        return datetime.fromisoformat(res[0].replace('Z', '+00:00')).strftime("%d-%m-%Y %H:%M:%S")
                    except:
                        return res[0]
                return "Fecha Desconocida"
        except Exception:
            return "Error"

    def get_severity_distribution_by_scan(self, scan_id: int) -> List[Tuple[str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                names = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                res = []
                for idx, name in enumerate(names):
                    c = conn.execute(
                        "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = ?", (scan_id, idx)
                    ).fetchone()[0]
                    if c > 0:
                        res.append((name, c))
                return res
        except Exception:
            return []

    def get_top_vulns_by_scan(self, scan_id: int, limit: int = 5) -> List[Tuple[str, int]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute(
                    "SELECT name, COUNT(*) as count FROM vulnerabilities WHERE scan_id = ? "
                    "GROUP BY name ORDER BY count DESC LIMIT ?",
                    (scan_id, limit)
                ).fetchall()
        except Exception:
            return []

    def get_vulnerabilities_by_scan(self, scan_id: int) -> List[Any]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT name, description, severity, target_url, payload FROM vulnerabilities WHERE scan_id = ?",
                    (scan_id,)
                ).fetchall()
                int_to_sev = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

                class PDFVuln:
                    def __init__(self, name: str, desc: str, sev_int: int, url: str, payload: str) -> None:
                        self.vuln_type = name
                        self.name = name
                        self.description = desc
                        self.severity = int_to_sev.get(sev_int, "INFO")
                        self.url = url
                        self.payload = payload

                return [PDFVuln(*r) for r in rows]
        except Exception:
            return []