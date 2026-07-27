"""Generación de reportes. El render es puro (str in → str out); la escritura
a disco es una función aparte para poder testear sin tocar el filesystem.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from webvulnscanner import scoring
from webvulnscanner.models import Risk, ScanResult

_TITULOS = {
    Risk.ALTO: "PROBLEMAS CRÍTICOS",
    Risk.MEDIO: "PROBLEMAS MODERADOS",
    Risk.BAJO: "OBSERVACIONES (bajo impacto)",
    Risk.INFO: "INFORMACIÓN",
}


def render_texto(result: ScanResult, *, timestamp: str | None = None) -> str:
    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conteo = result.conteo()
    por_riesgo = result.por_riesgo()
    L: list[str] = []
    add = L.append

    add("=" * 70)
    add("  REPORTE DE ANÁLISIS DE SEGURIDAD WEB — WebVulnScanner 2.0")
    add("  Auditoría pasiva | Enfoque ético y académico")
    add("=" * 70)
    add(f"  Objetivo   : {result.dominio}")
    add(f"  IP         : {result.ip or 'N/A'}")
    add(f"  Servidor   : {result.servidor or 'N/A'}")
    add(f"  Fecha/Hora : {ts}")
    ltr, pts = scoring.calcular(result)
    add(f"  Nota       : {ltr}  ({pts}/100)")
    add("=" * 70)
    add("\n  RESUMEN DE HALLAZGOS:")
    add(f"  {Risk.ALTO.emoji} Alto:             {conteo[Risk.ALTO]}")
    add(f"  {Risk.MEDIO.emoji} Medio:            {conteo[Risk.MEDIO]}")
    add(f"  {Risk.BAJO.emoji} Bajo:             {conteo[Risk.BAJO]}")
    add(f"  {Risk.INFO.emoji} Informativo:      {conteo[Risk.INFO]}")
    add(f"  {Risk.OK.emoji} Buenas prácticas: {conteo[Risk.OK]}")

    for nivel in (Risk.ALTO, Risk.MEDIO, Risk.BAJO, Risk.INFO):
        items = por_riesgo[nivel]
        if not items:
            continue
        add(f"\n{'─' * 70}")
        add(f"  {nivel.emoji} {_TITULOS[nivel]} ({len(items)})")
        add(f"{'─' * 70}")
        for i, h in enumerate(items, 1):
            add(f"\n  [{i}] [{h.modulo}] {h.hallazgo}")
            add(f"      ↳ {h.descripcion}")
            if h.referencia:
                add(f"      ↳ ref: {h.referencia}")

    ok = por_riesgo[Risk.OK]
    if ok:
        add(f"\n{'─' * 70}")
        add(f"  {Risk.OK.emoji} BUENAS PRÁCTICAS CONFIRMADAS ({len(ok)})")
        add(f"{'─' * 70}")
        for h in ok:
            add(f"  [✓] [{h.modulo}] {h.hallazgo}")

    add(f"\n{'=' * 70}")
    add("  AVISO LEGAL: uso académico y ético. Solo analice sitios propios o")
    add("  con autorización expresa.")
    add(f"{'=' * 70}\n")
    return "\n".join(L)


def render_json(result: ScanResult, *, timestamp: str | None = None) -> str:
    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conteo = {r.value: n for r, n in result.conteo().items()}
    ltr, pts = scoring.calcular(result)
    payload = {
        "meta": {
            "herramienta": "WebVulnScanner 2.0",
            "dominio": result.dominio,
            "ip": result.ip,
            "servidor": result.servidor,
            "timestamp": ts,
            "nota": ltr,
            "puntaje": pts,
        },
        "resumen": conteo,
        "hallazgos": [h.to_dict() for h in result.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def guardar(result: ScanResult, destino: Path | str = ".") -> tuple[Path, Path]:
    """Escribe .txt y .json y devuelve sus rutas. Única función con I/O."""
    destino = Path(destino)
    destino.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    base = f"reporte_{result.dominio.replace('.', '_')}_{datetime.datetime.now():%Y%m%d_%H%M%S}"
    ruta_txt = destino / f"{base}.txt"
    ruta_json = destino / f"{base}.json"
    ruta_txt.write_text(render_texto(result, timestamp=ts), encoding="utf-8")
    ruta_json.write_text(render_json(result, timestamp=ts), encoding="utf-8")
    return ruta_txt, ruta_json
