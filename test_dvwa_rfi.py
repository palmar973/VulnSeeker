import requests
import logging
from modules.rfi_scanner import RFIScanner
from core.scanner_types import Target, Vulnerability

# Configurar logs para ver la acción
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VulnSeeker")

# --- TUS DATOS DE MISION ---
# 1. PEGA AQUÍ TU COOKIE ACTUALIZADA
# Ejemplo: "PHPSESSID=tucookie12345; security=low"
MY_COOKIE = "PHPSESSID=bb70vinur0pfmsrqshdars9vm4; security=low"

# 2. La URL vulnerable de DVWA
# RFI suele ocurrir en parámetros como 'page', 'file', etc.
TARGET_URL = "http://localhost/vulnerabilities/fi/?page=include.php"


def run_surgical_strike():
    print(f"🍪 Cargando Cookie: {MY_COOKIE[:15]}...")
    print(f"🎯 Objetivo fijado: {TARGET_URL}")
    print("🚀 INICIANDO ATAQUE RFI...")

    # Instanciamos el escáner
    scanner = RFIScanner()

    # Preparamos el objetivo
    target = Target(url=TARGET_URL)

    # --- TRUCO: MONKEY PATCHING ---
    # Interceptamos requests para inyectar la cookie a la fuerza
    original_get = requests.Session.get

    def get_with_cookie(self, url, **kwargs):
        # Convertir string de cookie a diccionario
        cookie_dict = {}
        for item in MY_COOKIE.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                cookie_dict[k] = v

        kwargs['cookies'] = cookie_dict
        # Aseguramos verify=False para localhost
        kwargs['verify'] = False
        return original_get(self, url, **kwargs)

    # Reemplazamos temporalmente el método get de Session
    requests.Session.get = get_with_cookie

    # --- EJECUTAR ATAQUE ---
    try:
        vulns = scanner.run(target)
    except Exception as e:
        print(f"Error crítico: {e}")
        vulns = []

    # Restaurar (buena práctica)
    requests.Session.get = original_get

    print("\n" + "=" * 50)
    if vulns:
        print(f"🔥 ¡IMPACTO CONFIRMADO! ({len(vulns)} vulnerabilidades)")
        for v in vulns:
            print(f"🛑 Tipo: {v.name}")
            print(f"💣 Payload: {v.payload}")
            print(f"📄 Evidencia: {v.evidence}")
            print("-" * 30)
    else:
        print("❌ NO SE CONFIRMÓ RFI.")
        print("\nPosibles causas:")
        print("1. La cookie expiró (Saca una nueva con F12).")
        print("2. DVWA Security no está en 'Low'.")
        print("3. (Muy probable) La configuración PHP 'allow_url_include' está OFF en el contenedor.")
    print("=" * 50)


if __name__ == "__main__":
    run_surgical_strike()