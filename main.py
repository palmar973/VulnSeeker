import sys
# Desactivamos advertencias de SSL para que no ensucien la consola en sitios HTTPS de prueba
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.engine import VulnSeekerEngine
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner


def main() -> None:
    print("\n" + "=" * 60)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(" Fase 3: Prueba de Fuego XSS (Google Target)")
    print("=" * 60 + "\n")

    # 1. Inicialización
    engine = VulnSeekerEngine()

    # 2. Carga del Arsenal
    engine.register_module(SQLInjectionScanner())
    engine.register_module(XSSScanner())

    # 3. Definición del Objetivo (NUEVO)
    # Usamos el Nivel 1 del juego XSS de Google.
    # Es un objetivo HTTPS, así que probaremos también la capacidad SSL de tu motor.
    # El parámetro 'query' es vulnerable y refleja todo.
    target_url: str = "https://xss-game.appspot.com/level1/frame?query=test"

    try:
        # 4. Ejecución
        print(f"[TEST] Lanzando ataque contra: {target_url}")

        # crawl=False para ir directo al grano.
        results = engine.scan(target_url, crawl=False)

        # 5. Reporte Consolidado
        print("\n" + "=" * 60)
        print(f" RESUMEN DE EJECUCIÓN: {len(results)} hallazgos totales")
        print("=" * 60)

        if results:
            for i, v in enumerate(results):
                # Uso colores básicos si la terminal lo soporta, o formato claro
                print(f"#{i + 1} [{v.severity.value}] {v.name}")
                print(f"    Ubicación: {v.target_url}")
                print(f"    Evidencia: {v.evidence}")
                print("-" * 40)
        else:
            print("No se encontraron vulnerabilidades.")

    except KeyboardInterrupt:
        print("\n[!] Abortado.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()