import sys
import os
import logging

# Ajuste de sys.path porque se ejecuta desde subcarpeta
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.crawler import WebCrawler

# Configuro el logging para ver todo lo que pasa en la consola.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def test_crawler_standalone() -> None:
    """
    Prueba de aislamiento del Crawler.
    Objetivo: Verificar que navega, encuentra enlaces y respeta el límite de páginas.
    """

    # Sitio de pruebas público para evitar líos legales
    target_url: str = "http://books.toscrape.com/index.html"

    print(f"--- Iniciando Prueba Unitaria Manual del Crawler ---")
    print(f"Objetivo: {target_url}")

    try:
        # Instancio el crawler.
        # Le pongo un límite bajo (5 páginas) para que la prueba sea rápida.
        crawler = WebCrawler(start_url=target_url, max_pages=5)

        # Ejecuto el método start y capturo los resultados.
        results: list[str] = crawler.start()

        print("\n" + "=" * 50)
        print(f"RESULTADOS DE LA PRUEBA")
        print("=" * 50)
        print(f"Total de URLs descubiertas: {len(results)}")
        print("-" * 30)

        for i, url in enumerate(results):
            print(f"[{i + 1}] {url}")

        print("=" * 50)

        # Validaciones básicas de éxito
        if len(results) > 1:
            print("✅ PRUEBA EXITOSA: El crawler encontró múltiples enlaces.")
        else:
            print("❌ PRUEBA FALLIDA: El crawler no expandió la búsqueda.")

    except Exception as e:
        print(f"❌ ERROR CRÍTICO DURANTE LA PRUEBA: {e}")


if __name__ == "__main__":
    test_crawler_standalone()