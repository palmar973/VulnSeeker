import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.engine import VulnSeekerEngine
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from reports.report_generator import ReportGenerator


def main() -> None:
    print("\n" + "=" * 60)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(" Fase 4: Generación de Reportes JSON")
    print("=" * 60 + "\n")

    engine = VulnSeekerEngine()
    engine.register_module(SQLInjectionScanner())
    engine.register_module(XSSScanner())

    # Usamos el objetivo XSS que sabemos que funciona
    target_url: str = "https://xss-game.appspot.com/level1/frame?query=test"

    try:
        print(f"[TEST] Escaneando: {target_url}")
        results = engine.scan(target_url, crawl=False)

        print("\n" + "=" * 60)
        print(f" RESUMEN: {len(results)} hallazgos.")
        print("=" * 60)

        # --- NUEVA LÓGICA DE REPORTE ---
        if results:
            reporter = ReportGenerator()
            json_path = reporter.export_json(results, target_url)
            print(f"\n[+] Reporte guardado exitosamente en:\n    {json_path}")
        else:
            print("No hay vulnerabilidades para reportar.")

    except KeyboardInterrupt:
        print("\n[!] Abortado.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()