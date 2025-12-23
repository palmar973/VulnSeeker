import sys
from core.engine import VulnSeekerEngine
# from modules.dummy_module import DummyScanner # Lo comento, ya no jugamos.
from modules.sqli_module import SQLInjectionScanner


def main() -> None:
    print("\n" + "=" * 60)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(" Fase 2: SQL Injection Module Test")
    print("=" * 60 + "\n")

    # 1. Inicialización
    engine = VulnSeekerEngine()

    # 2. Carga del Arsenal Real
    sqli_module = SQLInjectionScanner()
    engine.register_module(sqli_module)

    # 3. Definición del Objetivo
    # CAMBIO IMPORTANTE: Usamos un sitio intencionalmente vulnerable a SQLi.
    # http://testphp.vulnweb.com/listproducts.php?cat=1 es un clásico para estas pruebas.
    target_url: str = "http://testphp.vulnweb.com/listproducts.php?cat=1"

    try:
        # 4. Ejecución
        # Desactivo el crawling (crawl=False) para probar el módulo SQLi directo al grano
        # sobre la URL que sé que tiene parámetros.
        print(f"[TEST] Lanzando ataque directo contra: {target_url}")
        results = engine.scan(target_url, crawl=False)

        # 5. Reporte
        print("\n" + "=" * 60)
        print(f" RESUMEN DE EJECUCIÓN: {len(results)} hallazgos totales")
        print("=" * 60)

        if results:
            for i, v in enumerate(results):
                print(f"#{i + 1} [{v.severity.value}] {v.name}")
                print(f"    Ubicación: {v.target_url}")
                print(f"    Evidencia: {v.evidence}")
        else:
            print("No se encontraron vulnerabilidades (¿El sitio se arregló o falló la lógica?).")

    except KeyboardInterrupt:
        print("\n[!] Abortado.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()