"""Orquestación de herramientas externas (nuclei, nmap, testssl, wpscan…).

Filosofía: no reimplementar motores maduros, sino ejecutarlos si están
instalados y normalizar su salida a `Finding`. Si el binario no está, el
módulo se omite en silencio (degradación elegante).
"""

from __future__ import annotations

import logging
import shutil
import subprocess

log = logging.getLogger("webvulnscanner.tools")


def disponible(binario: str) -> bool:
    return shutil.which(binario) is not None


def ejecutar(cmd: list[str], *, timeout: int = 120) -> str | None:
    """Ejecuta un comando y devuelve su stdout, o None si el binario no está,
    falla o se pasa de tiempo. Nunca lanza: un fallo de herramienta externa no
    debe abortar el escaneo."""
    if not disponible(cmd[0]):
        log.info("  [i] '%s' no instalado — módulo omitido", cmd[0])
        return None
    try:
        proc = subprocess.run(  # noqa: S603 — comando construido por nosotros, no por el usuario
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("  [x] '%s' falló: %s", cmd[0], e)
        return None
    return proc.stdout
