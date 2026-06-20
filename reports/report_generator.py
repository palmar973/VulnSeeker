import json
import os
from datetime import datetime
from dataclasses import asdict
from core.models import Vulnerability


class ReportGenerator:
    """
    Encargado de transformar los resultados del escaneo en archivos persistentes.
    Soporta formato JSON para integración con otras herramientas.
    """

    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        # Crea la carpeta de resultados si no existe
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def export_json(self, vulnerabilities: list[Vulnerability], target_url: str) -> str:
        """
        Genera un archivo JSON con los hallazgos.
        Devuelve la ruta del archivo generado.
        """

        # --- CORRECCIÓN DE SERIALIZACIÓN ---
        # Convertimos los objetos Vulnerability a diccionarios y
        # manualmente convertimos el Enum 'severity' a su valor string.
        findings_processed = []
        for v in vulnerabilities:
            v_dict = asdict(v)
            # Aquí está la clave: extraemos el .value del Enum (ej: "HIGH")
            v_dict['severity'] = v.severity.value
            findings_processed.append(v_dict)

        data = {
            "target": target_url,
            "scan_date": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "findings": findings_processed
        }

        # Generamos un nombre de archivo único basado en la fecha
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return filepath
