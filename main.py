import sys
from core.engine import VulnSeekerEngine
from modules.dummy_module import DummyScanner


def main() -> None:
    print("--- Arrancando VulnSeeker ---")

    # Instancio el cerebro.
    engine = VulnSeekerEngine()

    # Instancio mi módulo de prueba.
    # En el futuro, aquí iteraré sobre la carpeta modules para cargarlos dinámicamente.
    dummy = DummyScanner()
    engine.register_module(dummy)

    # URL de prueba.
    target_url: str = "http://localhost:8000"

    try:
        # ¡Fuego!
        results = engine.scan(target_url)

        print(f"\n[+] Resumen: Encontré {len(results)} problemas.")

        for v in results:
            print(f" - [{v.severity.value}] {v.name}")
            print(f"   URL: {v.target_url}")
            # Solo imprimo evidencia si existe, gracias al chequeo de tipo str | None
            if v.evidence:
                print(f"   Evidencia: {v.evidence}")

    except KeyboardInterrupt:
        print("\n[!] Me mandaron a parar. Abortando.")
        sys.exit(0)


if __name__ == "__main__":
    main()