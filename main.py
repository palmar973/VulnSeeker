import sys
import argparse
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.engine import VulnSeekerEngine
from core.module_registry import get_default_modules
from reports.report_generator import ReportGenerator
from core.config import GlobalConfig
from core.db_manager import DatabaseManager

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("VulnSeeker")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="VulnSeeker - Escáner de Vulnerabilidades Web (JSON + SQLite)",
        epilog="Ejemplo: python main.py -u http://testphp.vulnweb.com --crawl"
    )
    parser.add_argument("-u", "--url", required=True, help="URL objetivo completa")
    parser.add_argument("--crawl", action="store_true", help="Habilitar Crawler")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    target_url = args.url
    use_crawler = args.crawl

    print("\n" + "=" * 70)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(f" Target: {target_url}")
    print(f" Mode: {'CRAWLING + SCAN' if use_crawler else 'SINGLE URL SCAN'}")
    print(f" Threads: {GlobalConfig.MAX_THREADS}")
    print("=" * 70 + "\n")

    engine = VulnSeekerEngine()

    for module in get_default_modules():
        engine.register_module(module)

    try:
        print(f"[*] Iniciando motor de análisis...")
        results = engine.scan(target_url, crawl=use_crawler)

        print("\n" + "=" * 70)
        print(f" RESUMEN DE EJECUCIÓN: {len(results)} hallazgos totales")
        print("=" * 70)

        if results:
            severity_counts = {}
            for v in results:
                print(f"[{v.severity.value}] {v.name} -> {v.target_url}")
                severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

            print("-" * 50)
            print("Desglose por Severidad:")
            for sev, count in severity_counts.items():
                print(f"  {sev}: {count}")

            reporter = ReportGenerator(output_dir=GlobalConfig.REPORTS_DIR)
            json_path = reporter.export_json(results, target_url)
            print(f"\n[+] Reporte JSON guardado en:\n    {json_path}")

            print("[*] Guardando en Base de Datos Histórica...")
            db = DatabaseManager()
            scan_id = db.save_scan_results(target_url, results)
            print(f"[+] Datos persistidos en SQLite (Scan ID: {scan_id})")

        else:
            print("[-] No se encontraron vulnerabilidades en el objetivo.")

    except KeyboardInterrupt:
        print("\n[!] Operación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error crítico no controlado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()