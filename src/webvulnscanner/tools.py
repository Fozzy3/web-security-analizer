"""Orquestación de herramientas externas (nuclei, nmap, testssl, wpscan…).

Filosofía: no reimplementar motores maduros, sino ejecutarlos si están
instalados y normalizar su salida a `Finding`. Si el binario no está, el
módulo se omite en silencio (degradación elegante).
"""

from __future__ import annotations

import importlib.util
import logging
import os
import shutil
import subprocess
from collections.abc import Callable

log = logging.getLogger("webvulnscanner.tools")

# Rutas candidatas del socket GMP de gvmd (sobreescribibles con $GVM_SOCKET).
_GVM_SOCKETS = ("/run/gvmd/gvmd.sock", "/var/run/gvmd/gvmd.sock")


def disponible(binario: str) -> bool:
    return shutil.which(binario) is not None


def _importable(paquete: str) -> bool:
    return importlib.util.find_spec(paquete) is not None


def gvm_socket() -> str | None:
    """Ruta del socket GMP de gvmd si existe, o None. $GVM_SOCKET tiene prioridad."""
    entorno = os.environ.get("GVM_SOCKET")
    candidatos = [entorno] if entorno else list(_GVM_SOCKETS)
    return next((c for c in candidatos if c and os.path.exists(c)), None)


def _openvas_disponible() -> bool:
    return _importable("gvm") and gvm_socket() is not None


# Motor externo opcional → (etiqueta, ¿disponible?, comando de instalación).
# Fuente única para el rastreo de cobertura, el aviso de instalación y `--check-tools`.
MOTORES: dict[str, tuple[str, Callable[[], bool], str]] = {
    "sslyze": ("sslyze", lambda: _importable("sslyze"), "pip install sslyze"),
    "schemathesis": ("schemathesis", lambda: _importable("schemathesis"), "pip install schemathesis"),
    "wappalyzer": ("Wappalyzer", lambda: _importable("Wappalyzer"), "pip install python-Wappalyzer"),
    "nuclei": (
        "nuclei",
        lambda: disponible("nuclei"),
        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    "subfinder": (
        "subfinder",
        lambda: disponible("subfinder"),
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "testssl": (
        "testssl.sh",
        lambda: disponible("testssl.sh"),
        "git clone --depth 1 https://github.com/testssl/testssl.sh ~/.local/testssl.sh "
        "&& ln -s ~/.local/testssl.sh/testssl.sh ~/.local/bin/",
    ),
    "nmap": ("nmap", lambda: disponible("nmap"), "sudo dnf install -y nmap   # o: sudo apt install -y nmap"),
    "wpscan": ("wpscan", lambda: disponible("wpscan"), "sudo gem install wpscan   # requiere Ruby"),
    "openvas": (
        "OpenVAS/GVM",
        _openvas_disponible,
        "pip install python-gvm  +  instancia GVM (Greenbone) con socket en /run/gvmd/gvmd.sock "
        "y credenciales en $GVM_USERNAME/$GVM_PASSWORD",
    ),
}


def motor_disponible(clave: str) -> bool:
    """True si el motor está instalado (o si la clave no es un motor gateado)."""
    m = MOTORES.get(clave)
    return m[1]() if m else True


def motores_faltantes() -> list[tuple[str, str]]:
    """[(etiqueta, comando de instalación)] de los motores opcionales no instalados."""
    return [(etq, cmd) for etq, chk, cmd in MOTORES.values() if not chk()]


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
