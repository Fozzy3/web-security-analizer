"""Baseline de supresión: ignora hallazgos ya revisados/aceptados.

Imprescindible para CI: tras un primer escaneo se acepta un baseline y los
escaneos siguientes solo muestran lo NUEVO. La huella es estable — depende de
(módulo, hallazgo, referencia), NO de la descripción (que puede variar entre
ejecuciones sin cambiar el hallazgo).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from webvulnscanner.models import Finding


def huella(f: Finding) -> str:
    """Identificador estable de un hallazgo (16 hex)."""
    base = f"{f.modulo}|{f.hallazgo}|{f.referencia or ''}"
    return hashlib.sha256(base.encode()).hexdigest()[:16]


def cargar(ruta: Path | str) -> set[str]:
    """Lee las huellas de un baseline. Archivo inexistente → conjunto vacío."""
    ruta = Path(ruta)
    if not ruta.exists():
        return set()
    huellas: set[str] = set()
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if linea and not linea.startswith("#"):
            huellas.add(linea.split()[0])  # la huella; ignora comentario inline
    return huellas


def filtrar(findings: list[Finding], huellas: set[str]) -> list[Finding]:
    """Devuelve los hallazgos que NO están en el baseline."""
    return [f for f in findings if huella(f) not in huellas]


def escribir(ruta: Path | str, findings: list[Finding]) -> None:
    """Escribe las huellas de `findings` como baseline aceptado."""
    lineas = ["# WebVulnScanner baseline — hallazgos aceptados (uno por línea)"]
    lineas += [f"{huella(f)}  # {f.modulo}: {f.hallazgo}" for f in findings]
    Path(ruta).write_text("\n".join(lineas) + "\n", encoding="utf-8")
