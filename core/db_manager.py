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
import csv

logger = logging.getLogger("VulnSeeker.DB")


class DatabaseManager:
    """
    Gestor centralizado de base de datos SQLite para VulnSeeker.

    Implementa el patrón Singleton para garantizar una única conexión
    a lo largo de toda la aplicación. Gestiona scans, vulnerabilidades,
    subdominios y configuración del sistema.
    """
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            # Ruta absoluta para no depender del CWD
            base_dir = Path(__file__).resolve().parent.parent  # core/ -> raíz del proyecto
            self.db_path = (base_dir / GlobalConfig.REPORTS_DIR / "vulns.db").resolve()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Inicialización + migraciones automáticas."""
        self.db_path.parent.mkdir(exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")

            # Tabla scans con columna de tech (Fase 19)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    total_vulns INTEGER DEFAULT 0,
                    technologies TEXT DEFAULT 'Unknown'
                )
            """)

            # Tabla de subdominios (Fase 20)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    subdomain TEXT NOT NULL,
                    status TEXT DEFAULT 'LIVE',
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)

            # Vulnerabilidades asociadas a cada scan
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

            # KV de configuración
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            # Migración idempotente
            try:
                conn.execute("ALTER TABLE scans ADD COLUMN technologies TEXT DEFAULT 'Unknown'")
            except sqlite3.OperationalError:
                pass  # Ya existe

            conn.commit()
            logger.info("🗄️ DB inicializada/migrada correctamente.")

    # Fase 20: subdominios
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

    def get_scan_technologies(self, scan_id: int) -> str:
        """Devuelve las tecnologías detectadas para un scan específico."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT technologies FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return res[0] if res and res[0] else "Análisis no disponible"
        except Exception:
            return "Desconocido"

    def set_setting(self, key: str, value: str) -> None:
        """Guarda un par clave/valor de configuración."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
                conn.commit()
        except Exception as e:
            logger.error(f"❌ Error guardando setting {key}: {e}")

    def get_setting(self, key: str, default: str = "") -> str:
        """Recupera un valor de configuración o retorna default."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
                return res[0] if res else default
        except Exception:
            return default

    def save_api_key(self, api_key: str) -> None:
        """Persiste la API key de Groq en la tabla settings."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                           ("groq_api_key", api_key))
                conn.commit()
        except Exception:
            pass

    def get_api_key(self) -> Optional[str]:
        """Recupera la API key de Groq almacenada, o None si no existe."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT value FROM settings WHERE key = ?", ("groq_api_key",)).fetchone()
                return res[0] if res else None
        except Exception:
            return None

    def get_all_scans(self) -> List[Tuple[int, str, str, int]]:
        """Devuelve todos los scans ordenados por fecha descendente.

        Returns:
            Lista de tuplas (id, fecha, url_objetivo, total_vulns).
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute(
                    "SELECT s.id, s.scan_date, s.target_url, s.total_vulns FROM scans s ORDER BY s.scan_date DESC"
                ).fetchall()
        except Exception:
            return []

    def get_unique_targets(self) -> List[str]:
        """Devuelve la lista de URLs únicas escaneadas."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                return [row[0] for row in
                        conn.execute("SELECT DISTINCT target_url FROM scans ORDER BY target_url").fetchall()]
        except Exception:
            return []

    def get_scans_by_target(self, target_url: str) -> List[Tuple[int, str, str, int]]:
        """Filtra los scans realizados contra una URL específica."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute(
                    "SELECT s.id, s.scan_date, s.target_url, s.total_vulns FROM scans s WHERE s.target_url = ? "
                    "ORDER BY s.scan_date DESC", (target_url,)
                ).fetchall()
        except Exception:
            return []

    def get_scan_stats(self, scan_id: int) -> Dict[str, int]:
        """Devuelve estadísticas de severidad para un scan.

        Returns:
            Dict con claves: total_vulns, critical_high, medium_low.
        """
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
        """Devuelve la URL objetivo de un scan por su ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT target_url FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return res[0] if res else "Unknown"
        except Exception:
            return "Error"

    def get_scan_date(self, scan_id: int) -> str:
        """Devuelve la fecha del scan formateada como DD-MM-YYYY HH:MM:SS."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                res = conn.execute("SELECT scan_date FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if res:
                    try:
                        return datetime.fromisoformat(res[0].replace('Z', '+00:00')).strftime("%d-%m-%Y %H:%M:%S")
                    except (ValueError, TypeError):
                        return res[0]
                return "Fecha Desconocida"
        except Exception:
            return "Error"

    def get_severity_distribution_by_scan(self, scan_id: int) -> List[Tuple[str, int]]:
        """Devuelve la distribución de severidades para un scan.

        Returns:
            Lista de tuplas (nombre_severidad, cantidad) solo para severidades con count > 0.
        """
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
        """Devuelve las vulnerabilidades más frecuentes de un scan.

        Args:
            scan_id: ID del scan a consultar.
            limit: Cantidad máxima de resultados (por defecto 5).
        """
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
        """Devuelve las vulnerabilidades de un scan como objetos PDFVuln.

        Cada objeto tiene atributos: vuln_type, name, description, severity, url, payload.
        Usado internamente por el generador de reportes PDF.
        """
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

    def delete_scan(self, scan_id: int) -> bool:
        """Elimina un scan y sus datos asociados."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
                conn.execute("DELETE FROM subdomains WHERE scan_id = ?", (scan_id,))
                conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"❌ Error eliminando scan {scan_id}: {e}")
            return False

    def nuke_database(self) -> bool:
        """
        Borra todo el historial (scans, vulns, subdomains) pero conserva settings.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM vulnerabilities;")
                conn.execute("DELETE FROM subdomains;")
                conn.execute("DELETE FROM scans;")
                conn.execute("COMMIT")
                conn.execute("VACUUM;")
            return True
        except Exception as e:
            logger.error(f"☢️ Error haciendo NUKE DB: {e}")
            return False

    def export_to_csv(self, output_path: str, scan_id: int | None = None) -> bool:
        """
        Exporta hallazgos a CSV profesional para Excel.
        Si scan_id es None, exporta el escaneo más reciente.

        Estructura del CSV:
        - Bloque de metadata (scan info)
        - Tabla de hallazgos con columnas bien separadas
        - Resumen de severidades al final
        """
        try:
            import csv

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Si no se especifica scan_id, usar el más reciente
                if scan_id is None:
                    result = cursor.execute(
                        "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    if not result:
                        logger.error("No hay escaneos en la base de datos.")
                        return False
                    scan_id = result[0]

                # Info del scan
                scan_info = cursor.execute(
                    "SELECT id, scan_date, target_url FROM scans WHERE id = ?",
                    (scan_id,)
                ).fetchone()
                if not scan_info:
                    logger.error(f"Scan {scan_id} no encontrado.")
                    return False

                sid, scan_date, target_url = scan_info

                # Hallazgos ordenados por severidad (mayor a menor)
                query = """
                    SELECT v.name, v.severity, v.description, v.target_url, v.payload
                    FROM vulnerabilities v
                    WHERE v.scan_id = ?
                    ORDER BY v.severity DESC, v.name ASC
                """
                rows = cursor.execute(query, (scan_id,)).fetchall()

            sev_map = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

            # Contar por severidad
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for _, sev, *_ in rows:
                sev_text = sev_map.get(sev, "UNKNOWN")
                if sev_text in sev_counts:
                    sev_counts[sev_text] += 1

            with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)

                # ── Bloque de metadata ──
                writer.writerow(["VULNSEEKER — REPORTE DE AUDITORÍA DAST"])
                writer.writerow([])
                writer.writerow(["Objetivo", target_url])
                writer.writerow(["Scan ID", f"#{sid}"])
                writer.writerow(["Fecha", scan_date])
                writer.writerow(["Total Vulnerabilidades", len(rows)])
                writer.writerow(["Críticas/Alta",
                                 sev_counts["CRITICAL"] + sev_counts["HIGH"]])
                writer.writerow(["Media/Baja",
                                 sev_counts["MEDIUM"] + sev_counts["LOW"]])
                writer.writerow([])

                # ── Resumen por severidad ──
                writer.writerow(["DISTRIBUCIÓN POR SEVERIDAD"])
                for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    if sev_counts[sev_name] > 0:
                        writer.writerow([sev_name, sev_counts[sev_name]])
                writer.writerow([])

                # ── Tabla de hallazgos ──
                headers = ["#", "Vulnerabilidad", "Severidad", "URL", "Descripción",
                           "Payload"]
                writer.writerow(headers)

                for idx, (v_name, v_sev, v_desc, v_url, v_pay) in enumerate(rows, 1):
                    sev_text = sev_map.get(v_sev, "UNKNOWN")

                    # Limpieza de texto para Excel
                    clean_desc = (str(v_desc).replace("\n", " ").replace("\r", "")
                                  .strip()[:200] if v_desc else "")
                    clean_pay = (str(v_pay).replace("\n", " ").replace("\r", "")
                                 .strip()[:150] if v_pay else "")
                    clean_url = str(v_url).strip()[:120] if v_url else ""

                    writer.writerow([
                        idx, v_name, sev_text, clean_url, clean_desc, clean_pay
                    ])

                # ── Footer ──
                writer.writerow([])
                writer.writerow([f"Generado por VulnSeeker Enterprise — {scan_date}"])

            return True

        except Exception as e:
            logger.error(f"❌ Error exportando CSV: {e}")
            return False


