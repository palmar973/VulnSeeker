import sys
from core.engine import VulnSeekerEngine
from modules.dummy_module import DummyScanner


def main() -> None:
    print("\n" + "=" * 60)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(" Arquitectura: Modular Microkernel | Crawler: BFS Integration")
    print("=" * 60 + "\n")

    # 1. Inicialización del Motor (El Cerebro)
    engine = VulnSeekerEngine()

    # 2. Carga de Módulos (El Arsenal)
    # Cargo el módulo Dummy para verificar que el pipeline de datos fluye bien.
    dummy = DummyScanner()
    engine.register_module(dummy)

    # 3. Definición del Objetivo
    # Uso el sandbox 'books.toscrape.com' para validar el crawling real sin riesgos legales.
    target_url: str = "http://books.toscrape.com/index.html"

    try:
        # 4. Ejecución (Crawling + Scanning)
        # El engine mapeará el sitio y luego atacará cada página encontrada.
        results = engine.scan(target_url, crawl=True)

        # 5. Reporte Final en Consola
        print("\n" + "=" * 60)
        print(f" RESUMEN DE EJECUCIÓN: {len(results)} hallazgos totales")
        print("=" * 60)

        if results:
            for i, v in enumerate(results):
                print(f"#{i + 1} [{v.severity.value}] {v.name}")
                print(f"    Ubicación: {v.target_url}")
                # Imprimo la evidencia solo si existe.
                if v.evidence:
                    print(f"    Evidencia: {v.evidence}")
        else:
            print("No se encontraron vulnerabilidades.")

    except KeyboardInterrupt:
        print("\n[!] Operación abortada por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error fatal no controlado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()