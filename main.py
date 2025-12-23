import sys
import argparse
import urllib3

# Desactivamos advertencias de SSL para pruebas en entornos locales o laboratorios
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.engine import VulnSeekerEngine
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from reports.report_generator import ReportGenerator
from core.config import GlobalConfig


def parse_arguments():
    """
    Configura y procesa los argumentos de línea de comandos.
    """
    parser = argparse.ArgumentParser(
        description="VulnSeeker - Escáner de Vulnerabilidades Web Modular y Automatizado",
        epilog="Ejemplo de uso: python main.py -u http://testphp.vulnweb.com --crawl"
    )

    # Argumento obligatorio: La URL (-u o --url)
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="URL objetivo completa (ej: http://sitio.com/pagina.php?id=1)"
    )

    # Argumento opcional: Activar Crawler (--crawl)
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Habilitar el Crawler para descubrir enlaces antes de atacar."
    )

    return parser.parse_args()


def main() -> None:
    # 1. Procesar argumentos de la terminal
    args = parse_arguments()
    target_url = args.url
    use_crawler = args.crawl

    print("\n" + "=" * 70)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(f" Target: {target_url}")
    print(f" Mode: {'CRAWLING + SCAN' if use_crawler else 'SINGLE URL SCAN'}")
    print("=" * 70 + "\n")

    # 2. Inicialización del Engine
    engine = VulnSeekerEngine()

    # 3. Carga del Arsenal
    engine.register_module(SQLInjectionScanner())
    engine.register_module(XSSScanner())

    try:
        # 4. Ejecución
        print(f"[*] Iniciando motor de análisis...")

        # El engine recibe la URL y la decisión de usar crawler o no
        results = engine.scan(target_url, crawl=use_crawler)

        # 5. Reporte en Consola
        print("\n" + "=" * 70)
        print(f" RESUMEN DE EJECUCIÓN: {len(results)} hallazgos totales")
        print("=" * 70)

        if results:
            for i, v in enumerate(results):
                print(f"#{i + 1} [{v.severity.value}] {v.name}")
                print(f"    Ubicación: {v.target_url}")
                # Mostramos solo los primeros 100 caracteres de evidencia para no ensuciar la consola
                evidence_preview = (v.evidence[:100] + '...') if v.evidence and len(v.evidence) > 100 else v.evidence
                print(f"    Evidencia: {evidence_preview}")
                print("-" * 50)

            # 6. Generación de Reporte JSON
            # Usamos la constante global para el directorio
            reporter = ReportGenerator(output_dir=GlobalConfig.REPORTS_DIR)
            json_path = reporter.export_json(results, target_url)
            print(f"\n[+] Reporte detallado guardado en:\n    {json_path}")

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