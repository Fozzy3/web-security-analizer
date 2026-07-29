"""API REST opcional (FastAPI).

Levantar con:  uvicorn webvulnscanner.api:app --reload
Requiere:      pip install -e ".[api]"

Expone el escaneo COMPLETO (pasivo + activo) como servicio.

⚠ SEGURIDAD: la API corre módulos ACTIVOS (envían peticiones de prueba al
objetivo). Un endpoint abierto es un vector de abuso (SSRF/DoS-as-a-service):
despliéguela SOLO en red confiable y sobre objetivos propios o autorizados.
"""

from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from webvulnscanner import __version__, scoring
from webvulnscanner.orchestrator import MODULOS, MODULOS_ACTIVOS, run_scan
from webvulnscanner.report import render_json

app = FastAPI(title="WebVulnScanner API", version=__version__)

_MODULOS = [n for n, _ in MODULOS] + [n for n, _ in MODULOS_ACTIVOS]  # todos (pasivos + activos)


class ScanRequest(BaseModel):
    dominio: str
    activos: list[str] | None = None  # subconjunto de módulos; None = todos


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "modulos": _MODULOS}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    activos = set(req.activos) & set(_MODULOS) if req.activos else set(_MODULOS)
    try:
        # Corre TODOS los módulos (pasivos + activos). Ver aviso de seguridad del módulo.
        result = run_scan(req.dominio, activos=activos)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    ltr, pts = scoring.calcular(result)
    return {
        "nota": ltr,
        "puntaje": pts,
        "reporte": json.loads(render_json(result)),
    }
