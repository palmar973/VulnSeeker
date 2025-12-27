import sqlite3
import os
import logging
from datetime import datetime
from typing import List
from core.config import GlobalConfig
from core.scanner_types import Vulnerability

# Configuro el logger para que sepamos qué pasa en el disco.
logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Gestor de persistencia para VulnSeeker.
    Aquí decidí usar SQLite por ser ligero, portable y perfecto para una tesis.
    """

    def __init__(self, db_name: str = "vulnseeker.db") -> None:
        # Me aseguro de que el directorio de reportes exista por si acaso.
        if not os.path.exists(GlobalConfig.REPORTS_DIR):
            os.makedirs(GlobalConfig.REPORTS_DIR)

        self.db_path: str = os.path.join(GlobalConfig.REPORTS_DIR, db_name)
        self._init_db()

    def _init_db(self) -> None:
        """Crea las tablas si no existen. Uso relaciones de llave foránea."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Tabla de Escaneos (Cabecera)
                cursor.execute("""
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
                                   timestamp
                                   DATETIME
                                   NOT
                                   NULL,
                                   total_vulns
                                   INTEGER
                                   DEFAULT
                                   0
                               )
                               """)

                # Tabla de Vulnerabilidades (Detalle)
                # On Delete Cascade asegura que si borramos un escaneo, se limpian sus fallos.
                cursor.execute("""
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
                                   severity
                                   TEXT
                                   NOT
                                   NULL,
                                   url
                                   TEXT
                                   NOT
                                   NULL,
                                   evidence
                                   TEXT,
                                   FOREIGN
                                   KEY
                               (
                                   scan_id
                               ) REFERENCES scans
                               (
                                   id
                               ) ON DELETE CASCADE
                                   )
                               """)
                conn.commit()
                logger.debug("Base de datos inicializada y tablas verificadas.")
        except sqlite3.Error as e:
            logger.error(f"Error crítico inicializando la DB: {e}")

    def save_scan_results(self, target_url: str, vulnerabilities: List[Vulnerability]) -> int:
        """
        Guarda los resultados del Engine en una sola transacción atómica.
        Retorna el ID del escaneo generado.
        """
        scan_id: int = -1
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # 1. Insertamos el encabezado del escaneo.
                # Uso datetime.now() para que el dueño del super sepa cuándo auditó su web.
                cursor.execute(
                    "INSERT INTO scans (target_url, timestamp, total_vulns) VALUES (?, ?, ?)",
                    (target_url, datetime.now().isoformat(), len(vulnerabilities))
                )
                scan_id = cursor.lastrowid

                # 2. Insertamos cada hallazgo de forma masiva (executemany es más rápido).
                # Transformo la lista de objetos Vulnerability en una lista de tuplas.
                vuln_data = [
                    (scan_id, v.name, v.severity.value, v.target_url, v.evidence)
                    for v in vulnerabilities
                ]

                cursor.executemany(
                    """INSERT INTO vulnerabilities
                           (scan_id, name, severity, url, evidence)
                       VALUES (?, ?, ?, ?, ?)""",
                    vuln_data
                )

                conn.commit()
                logger.info(f"Persistencia exitosa: Escaneo #{scan_id} guardado con {len(vulnerabilities)} hallazgos.")
        except sqlite3.Error as e:
            logger.error(f"Error al guardar resultados en la base de datos: {e}")

        return scan_id

    def get_all_scans(self) -> List[tuple]:
        """Útil para la futura interfaz de historial en la GUI."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT * FROM scans ORDER BY timestamp DESC").fetchall()