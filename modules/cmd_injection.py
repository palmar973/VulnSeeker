import logging
import time

from core.models import ScannerModule, Vulnerability, Target, Severity
from modules.injection_points import collect_points

logger = logging.getLogger("VulnSeeker.CmdInjection")


class CommandInjectionScanner(ScannerModule):
    """
    Escáner de Inyección de Comandos (OS Command Injection).

    Emplea DOS estrategias complementarias sobre todos los vectores del objetivo
    (GET query, POST/GET form y JSON, vía :func:`collect_points`):

    - **Basada en contenido:** concatena operadores del shell (``;``, ``&&``, ``|``)
      con comandos cuya salida es reconocible (``whoami`` -> ``root``,
      ``cat /etc/passwd`` -> ``root:x:0:0``). Sólo reporta si la evidencia aparece
      tras el ataque y NO estaba en la respuesta baseline (descarta falsos positivos).
    - **Ciega basada en tiempo:** cuando el comando no refleja su salida, inyecta un
      retardo controlado (``sleep``/``ping``). Si la respuesta se demora de forma
      proporcional al retardo, y se confirma al duplicarlo, el parámetro es
      vulnerable. Esta técnica cubre los casos "ciegos" que la basada en contenido
      no puede ver.
    """

    # Nombres sospechosos cuando el objetivo no expone parámetros/formulario.
    FALLBACK_PARAMS = ['ip', 'host', 'domain', 'ping', 'addr', 'cmd', 'exec', 'target']

    # Valor benigno de partida; el payload se concatena a este.
    BENIGN = "127.0.0.1"

    # (payload, evidencia esperada) para la detección basada en contenido.
    CONTENT_PAYLOADS = [
        ("; whoami", "root"), ("; whoami", "www-data"),
        ("&& whoami", "root"), ("&& whoami", "www-data"),
        ("| whoami", "root"), ("| whoami", "www-data"),
        ("; cat /etc/passwd", "root:x:0:0"),
        ("&& cat /etc/passwd", "root:x:0:0"),
        ("| cat /etc/passwd", "root:x:0:0"),
    ]

    # Ciego time-based. {d} = retardo en segundos. Se cubren operadores de shell
    # de Linux (sleep) y de Windows (ping -n / timeout) para objetivos reales.
    TIME_DELAY = 5
    TIME_TEMPLATES = [
        "; sleep {d}", "&& sleep {d}", "| sleep {d}",
        "`sleep {d}`", "$(sleep {d})",
        "&& ping -c {d} 127.0.0.1", "& ping -n {d} 127.0.0.1",
    ]

    def __init__(self, enable_blind: bool = True) -> None:
        # El ciego time-based sólo añade latencia real en parámetros vulnerables:
        # los no vulnerables responden de inmediato y se descartan sin coste.
        self.enable_blind = enable_blind

    @property
    def name(self) -> str:
        return "OS Command Injection"

    @property
    def description(self) -> str:
        return ("Detecta ejecución remota de comandos (RCE) por contenido reflejado "
                "y de forma ciega mediante retardos de tiempo controlados.")

    def run(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        headers = dict(target.headers) if target.headers else {'User-Agent': 'VulnSeeker/1.0'}
        points = collect_points(target, fallback_params=self.FALLBACK_PARAMS)
        logger.info(f"🐚 CmdInjection: {len(points)} puntos de inyección en {target.url}")

        for pt in points:
            # Si el contenido ya delata el RCE, no hace falta la prueba ciega (más cara).
            if self._probe_content(pt, headers, vulns):
                continue
            if self.enable_blind:
                self._probe_time(pt, headers, vulns)

        return vulns

    def _probe_content(self, pt, headers, vulns) -> bool:
        """Detección basada en contenido con guarda de baseline anti falso positivo."""
        base = pt.send(self.BENIGN, headers=headers)
        baseline = base.text if base is not None else ""

        for payload, expected in self.CONTENT_PAYLOADS:
            attack_val = f"{self.BENIGN}{payload}"
            resp = pt.send(attack_val, headers=headers)
            if resp is None:
                continue
            if expected in resp.text and expected not in baseline:
                vulns.append(Vulnerability(
                    name="OS Command Injection (RCE)",
                    severity=Severity.CRITICAL,
                    description=(f"Se detectó Inyección de Comandos (RCE) por contenido.\n"
                                f"El servidor ejecutó: '{payload.strip()}'\n"
                                f"Evidencia encontrada: '{expected}'"),
                    target_url=pt.report_url,
                    evidence=f"Payload: {attack_val} | Found: {expected}",
                    payload=attack_val,
                ))
                logger.info(f"💥 ¡COMMAND INJECTION (contenido) en '{pt.param_name}'!")
                return True
        return False

    def _probe_time(self, pt, headers, vulns) -> bool:
        """Detección ciega: mide la latencia diferencial al inyectar un retardo.

        Confirma con el doble del retardo para descartar lentitudes puntuales de red
        (misma lógica proporcional que el SQLi ciego basado en tiempo)."""
        d = self.TIME_DELAY
        t_base = self._timed(pt, self.BENIGN, headers)
        if t_base is None:
            return False

        for tmpl in self.TIME_TEMPLATES:
            t1 = self._timed(pt, f"{self.BENIGN}{tmpl.format(d=d)}", headers)
            if t1 is None or t1 < t_base + d * 0.7:
                continue
            # Confirmación: al duplicar el retardo, la demora debe escalar también.
            t2 = self._timed(pt, f"{self.BENIGN}{tmpl.format(d=d * 2)}", headers)
            if t2 is not None and t2 >= t_base + d * 2 * 0.7:
                payload = f"{self.BENIGN}{tmpl.format(d=d)}"
                vulns.append(Vulnerability(
                    name="OS Command Injection (Blind Time-Based)",
                    severity=Severity.CRITICAL,
                    description=(f"El parámetro '{pt.param_name}' es vulnerable a RCE ciego: "
                                f"inyectar retardos controlados ({d}s y {d * 2}s) produjo "
                                f"demoras proporcionales en la respuesta."),
                    target_url=pt.report_url,
                    evidence=(f"Baseline {t_base:.2f}s | delay({d})->{t1:.2f}s | "
                              f"delay({d * 2})->{t2:.2f}s"),
                    payload=payload,
                ))
                logger.info(f"💥 ¡COMMAND INJECTION ciego (tiempo) en '{pt.param_name}'!")
                return True
        return False

    def _timed(self, pt, value, headers):
        """Envía ``value`` y devuelve el tiempo de respuesta en segundos (None si falla)."""
        timeout = self.TIME_DELAY * 2 + 5
        start = time.perf_counter()
        resp = pt.send(value, headers=headers, timeout=timeout)
        if resp is None:
            return None
        return time.perf_counter() - start
