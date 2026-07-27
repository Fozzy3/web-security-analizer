"""API REST opcional (FastAPI).

Levantar con:  uvicorn webvulnscanner.api:app --reload
Requiere:      pip install -e ".[api]"

Expone el escaneo pasivo como servicio. El modo activo NO se expone por HTTP a
propósito: exigir autorización por objetivo no encaja en un endpoint abierto.
"""

from __future__ import annotations

import json

from fastapi import FastAPI
from pydantic import BaseModel

from webvulnscanner import __version__, scoring
from webvulnscanner.orchestrator import MODULOS, run_scan
from webvulnscanner.report import render_json

app = FastAPI(title="WebVulnScanner API", version=__version__)

_MODULOS = [n for n, _ in MODULOS]


class ScanRequest(BaseModel):
    dominio: str
    activos: list[str] | None = None  # subconjunto de módulos; None = todos (pasivos)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "modulos": _MODULOS}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    activos = set(req.activos) & set(_MODULOS) if req.activos else set(_MODULOS)
    result = run_scan(req.dominio, activos=activos)  # autorizado=False: solo pasivo
    ltr, pts = scoring.calcular(result)
    return {
        "nota": ltr,
        "puntaje": pts,
        "reporte": json.loads(render_json(result)),
    }
