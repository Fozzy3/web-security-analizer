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
import threading
import uuid
from collections.abc import Callable

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from webvulnscanner import __version__, informe, scoring
from webvulnscanner.models import Finding, Risk, ScanResult
from webvulnscanner.orchestrator import MODULOS, MODULOS_ACTIVOS, run_scan
from webvulnscanner.report import render_json

app = FastAPI(title="WebVulnScanner API", version=__version__)

_MODULOS = [n for n, _ in MODULOS] + [n for n, _ in MODULOS_ACTIVOS]  # todos (pasivos + activos)


class ScanRequest(BaseModel):
    dominio: str
    activos: list[str] | None = None  # subconjunto de módulos; None = todos


# Estado de los escaneos web en curso: job_id → último ScanResult (parcial o
# final), o None mientras arranca. ponytail: store en memoria de un solo proceso;
# si se escala a varias réplicas, migrar a Redis/DB.
_jobs: dict[str, ScanResult | None] = {}


def _spawn(fn: Callable[[], None]) -> None:
    """Corre el escaneo en segundo plano. Inyectable en tests (ejecución inline)."""
    threading.Thread(target=fn, daemon=True).start()


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


# ── Capa web: "pegá la URL y arranca" ─────────────────────────
# El escaneo completo (con OpenVAS) tarda 10-40 min: no cabe en un request
# síncrono. Flujo async: POST /ui/scan lanza el job y devuelve una URL de
# informe que se auto-refresca (el HTML ya trae <meta refresh> mientras hay
# módulos "en progreso") hasta que termina el análisis profundo.


def _ejecutar_job(job_id: str, dominio: str, activos: set[str]) -> None:
    def _parcial(r: ScanResult) -> None:
        _jobs[job_id] = r  # informe temprano: rápidos listos, lentos "en progreso"

    try:
        _jobs[job_id] = run_scan(dominio, activos=activos, on_parcial=_parcial)
    except Exception as e:  # noqa: BLE001 — el fallo se muestra en el informe, no tumba el server
        _jobs[job_id] = ScanResult(
            dominio=dominio,
            findings=[Finding("escaneo", "El escaneo falló", Risk.INFO, str(e))],
        )


@app.post("/ui/scan")
def ui_scan(req: ScanRequest) -> dict:
    activos = set(req.activos) & set(_MODULOS) if req.activos else set(_MODULOS)
    job_id = uuid.uuid4().hex
    _jobs[job_id] = None
    _spawn(lambda: _ejecutar_job(job_id, req.dominio, activos))
    return {"job_id": job_id, "url": f"/ui/report/{job_id}"}


@app.get("/ui/report/{job_id}", response_class=HTMLResponse)
def ui_report(job_id: str) -> HTMLResponse:
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    result = _jobs[job_id]
    if result is None:
        return HTMLResponse(_PAGINA_ESPERA)  # aún arrancando (recon + rápidos)
    return HTMLResponse(informe.generar(result))


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(_FORM)


# Página de arranque: se auto-refresca hasta que aparece el primer informe parcial.
_PAGINA_ESPERA = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Escaneo en curso…</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:15vh auto;padding:0 24px;
text-align:center;color:#334}h1{font-size:20px}p{color:#667}.sp{font-size:40px;
animation:g 1.2s linear infinite}@keyframes g{to{transform:rotate(360deg)}}</style></head>
<body><div class="sp">◐</div><h1>Escaneo en curso…</h1>
<p>Reconocimiento y análisis rápido en marcha. Esta página se actualiza sola;
el informe aparece en cuanto haya resultados y se completa cuando termina el
análisis profundo (OpenVAS puede tardar 10-40 min).</p></body></html>"""

# Formulario mínimo: pegá la URL y arranca. Sin dependencias extra (fetch + JS).
_FORM = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebVulnScanner — Escanear un sitio</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:14vh auto;padding:0 24px;color:#223}
h1{font-size:26px;margin:0 0 6px}p{color:#667;margin:0 0 24px}
form{display:flex;gap:10px}input{flex:1;padding:13px 15px;font-size:16px;border:1px solid #cbd2dc;
border-radius:10px}button{padding:13px 22px;font-size:16px;font-weight:600;color:#fff;background:#2563eb;
border:0;border-radius:10px;cursor:pointer}button:disabled{opacity:.6;cursor:progress}
small{display:block;margin-top:16px;color:#8a93a2}</style></head>
<body><h1>🛡️ WebVulnScanner</h1>
<p>Pegá la URL o el dominio y comenzá la auditoría (escaneo activo completo, OpenVAS incluido).</p>
<form onsubmit="return lanzar(event)">
  <input id="d" name="dominio" placeholder="ejemplo.com" required autofocus>
  <button id="b" type="submit">Escanear</button>
</form>
<small>Un escaneo completo tarda desde minutos hasta ~40 min (análisis profundo). Serás redirigido
al informe, que se actualiza solo.</small>
<script>
async function lanzar(e){
  e.preventDefault();
  const b=document.getElementById('b'); b.disabled=true; b.textContent='Iniciando…';
  const dominio=document.getElementById('d').value.trim();
  const r=await fetch('/ui/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({dominio})});
  if(!r.ok){b.disabled=false;b.textContent='Escanear';alert('Dominio inválido');return false;}
  location.href=(await r.json()).url;
  return false;
}
</script></body></html>"""
