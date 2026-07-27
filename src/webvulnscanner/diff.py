"""Comparación entre dos escaneos: qué apareció y qué se resolvió.

Detección de regresiones: correr la herramienta periódicamente y comparar
contra el reporte .json anterior. La identidad de un hallazgo es (módulo,
hallazgo).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from webvulnscanner.models import Finding, ScanResult


@dataclass
class DiffResult:
    nuevos: list[Finding]
    resueltos: list[Finding]
    sin_cambios: int


def _clave(f: Finding) -> tuple[str, str]:
    return (f.modulo, f.hallazgo)


def comparar(anterior: ScanResult, actual: ScanResult) -> DiffResult:
    ant = {_clave(f): f for f in anterior.findings}
    act = {_clave(f): f for f in actual.findings}
    nuevos = [act[k] for k in act if k not in ant]
    resueltos = [ant[k] for k in ant if k not in act]
    sin_cambios = len(set(ant) & set(act))
    return DiffResult(nuevos=nuevos, resueltos=resueltos, sin_cambios=sin_cambios)


def cargar_reporte(ruta: Path | str) -> ScanResult:
    payload = json.loads(Path(ruta).read_text(encoding="utf-8"))
    return ScanResult.from_json(payload)


def render_texto(d: DiffResult) -> str:
    L = ["=" * 60, "  DIFERENCIAS ENTRE ESCANEOS", "=" * 60]
    L.append(f"  🆕 Nuevos:      {len(d.nuevos)}")
    L.append(f"  ✅ Resueltos:   {len(d.resueltos)}")
    L.append(f"  ➖ Sin cambios: {d.sin_cambios}")
    if d.nuevos:
        L.append("\n  NUEVOS HALLAZGOS:")
        for f in d.nuevos:
            L.append(f"   + [{f.riesgo.value}] [{f.modulo}] {f.hallazgo}")
    if d.resueltos:
        L.append("\n  HALLAZGOS RESUELTOS:")
        for f in d.resueltos:
            L.append(f"   - [{f.riesgo.value}] [{f.modulo}] {f.hallazgo}")
    return "\n".join(L)
