import logging
from core.interfaces import ScannerModule
from core.scanner_types import Target, Vulnerability

# Configuro el logging básico aquí para ver qué pasa por consola mientras depuro.
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class VulnSeekerEngine:
    """
    Orquestador central.
    """

    def __init__(self) -> None:
        # Inicializo la lista vacía. Más vale ser explícito aquí.
        self.modules: list[ScannerModule] = []
        self.results: list[Vulnerability] = []
        logging.info("VulnSeeker Engine listo y a la espera.")

    def register_module(self, module: ScannerModule) -> None:
        # Aquí me aseguro de que no me metan cualquier clase que no sea un ScannerModule.
        # Python es dinámico, pero yo quiero orden.
        if not isinstance(module, ScannerModule):
            raise TypeError(f"Me intentaron pasar {type(module)} y yo solo acepto ScannerModule.")

        self.modules.append(module)
        logging.debug(f"Cargué el módulo: {module.name}")

    def scan(self, target_url: str) -> list[Vulnerability]:
        """
        Método principal que coordina el ataque.
        """
        # Creo el objeto Target aquí mismo. Asumo GET por defecto por ahora.
        target = Target(url=target_url)

        logging.info(f"Voy a empezar a escanear: {target.url}")
        logging.info(f"Tengo {len(self.modules)} módulos listos para disparar.")

        for module in self.modules:
            try:
                logging.info(f"Lanzando módulo: {module.name}...")

                # Aquí es donde ocurre la magia (o el desastre si el módulo está mal hecho).
                found_vulns: list[Vulnerability] = module.run(target)

                if found_vulns:
                    logging.warning(f"  -> ¡Ojo! {module.name} encontró {len(found_vulns)} cosas.")
                    self.results.extend(found_vulns)
                else:
                    logging.info(f"  -> {module.name} no encontró nada. Limpio.")

            except Exception as e:
                # Si un módulo falla, no quiero que se caiga todo el programa.
                # Lo logueo y sigo con el siguiente. La resiliencia es clave.
                logging.error(f"¡Ups! El módulo {module.name} explotó: {e}")

        logging.info("Terminé el escaneo. Devolviendo resultados.")
        return self.results