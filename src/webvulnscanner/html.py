"""Render de reporte a HTML autocontenido (un solo archivo, sin dependencias).

Todo el contenido que proviene de servidores remotos (hallazgos, evidencia) se
escapa con html.escape: el propio reporte no debe ser vector de XSS.
"""

from __future__ import annotations

import datetime
from html import escape

from webvulnscanner import scoring
from webvulnscanner.models import Finding, Risk, ScanResult

_COLOR = {
    Risk.ALTO: "#ef4444",
    Risk.MEDIO: "#f59e0b",
    Risk.BAJO: "#22c55e",
    Risk.INFO: "#3b82f6",
    Risk.OK: "#10b981",
}
_ETIQUETA = {
    Risk.ALTO: "Alto",
    Risk.MEDIO: "Medio",
    Risk.BAJO: "Bajo",
    Risk.INFO: "Info",
    Risk.OK: "OK",
}
_NOTA_COLOR = {"A": "#10b981", "B": "#22c55e", "C": "#f59e0b", "D": "#f97316", "E": "#ef4444", "F": "#dc2626"}


def _tarjeta(f: Finding) -> str:
    color = _COLOR[f.riesgo]
    ref = (
        f'<a href="{escape(f.referencia)}" target="_blank" rel="noopener">{escape(f.referencia)}</a>'
        if f.referencia
        else ""
    )
    return f"""
    <div class="card" style="border-left-color:{color}">
      <div class="card-top">
        <span class="badge" style="background:{color}">{f.riesgo.emoji} {_ETIQUETA[f.riesgo]}</span>
        <span class="modulo">{escape(f.modulo)}</span>
      </div>
      <div class="titulo">{escape(f.hallazgo)}</div>
      <div class="desc">{escape(f.descripcion)}</div>
      {f'<div class="ref">🔗 {ref}</div>' if ref else ""}
    </div>"""


def render(result: ScanResult, *, timestamp: str | None = None) -> str:
    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conteo = result.conteo()
    por = result.por_riesgo()
    ltr, pts = scoring.calcular(result)
    nota_color = _NOTA_COLOR.get(ltr, "#64748b")

    tarjetas_riesgo = "".join(
        _tarjeta(f) for nivel in (Risk.ALTO, Risk.MEDIO, Risk.BAJO, Risk.INFO) for f in por[nivel]
    )
    tarjetas_ok = "".join(_tarjeta(f) for f in por[Risk.OK])

    cards_resumen = "".join(
        f'<div class="rc" style="border-color:{_COLOR[n]}">'
        f'<div class="rc-emoji">{n.emoji}</div>'
        f'<div class="rc-num" style="color:{_COLOR[n]}">{conteo[n]}</div>'
        f'<div class="rc-lbl">{_ETIQUETA[n]}</div></div>'
        for n in (Risk.ALTO, Risk.MEDIO, Risk.BAJO, Risk.INFO, Risk.OK)
    )

    return f"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de seguridad — {escape(result.dominio)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
  header {{ display: flex; align-items: center; gap: 24px; flex-wrap: wrap;
           border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 20px; }}
  .nota {{ font-size: 56px; font-weight: 800; width: 96px; height: 96px; border-radius: 16px;
          display: flex; align-items: center; justify-content: center; color: #fff;
          background: {nota_color}; flex-shrink: 0; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .meta {{ color: #94a3b8; font-size: 13px; line-height: 1.7; }}
  .resumen {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 24px; }}
  .rc {{ border: 2px solid; border-radius: 10px; padding: 10px; text-align: center; background: #1e293b; }}
  .rc-emoji {{ font-size: 18px; }}
  .rc-num {{ font-size: 26px; font-weight: 700; }}
  .rc-lbl {{ font-size: 11px; color: #94a3b8; }}
  h2 {{ font-size: 15px; margin: 28px 0 10px; color: #cbd5e1; }}
  .card {{ background: #1e293b; border-left: 4px solid; border-radius: 8px;
          padding: 12px 16px; margin-bottom: 10px; }}
  .card-top {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
  .badge {{ font-size: 11px; font-weight: 600; color: #fff; padding: 2px 8px; border-radius: 6px; }}
  .modulo {{ font-size: 11px; color: #94a3b8; }}
  .titulo {{ font-weight: 600; font-size: 14px; margin-bottom: 4px; word-break: break-word; }}
  .desc {{ font-size: 13px; color: #cbd5e1; line-height: 1.5; word-break: break-word; }}
  .ref {{ font-size: 12px; margin-top: 6px; word-break: break-all; }}
  .ref a {{ color: #60a5fa; }}
  footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #334155;
           color: #64748b; font-size: 12px; }}
  @media (max-width: 640px) {{ .resumen {{ grid-template-columns: repeat(3, 1fr); }} }}
</style></head>
<body><div class="wrap">
  <header>
    <div class="nota">{ltr}</div>
    <div>
      <h1>🔍 Reporte de seguridad web</h1>
      <div class="meta">
        <b>Objetivo:</b> {escape(result.dominio)}<br>
        <b>IP:</b> {escape(result.ip or "N/A")} &nbsp;·&nbsp; <b>Servidor:</b> {escape(result.servidor or "N/A")}<br>
        <b>Nota:</b> {ltr} ({pts}/100) &nbsp;·&nbsp; <b>Fecha:</b> {escape(ts)}
      </div>
    </div>
  </header>
  <div class="resumen">{cards_resumen}</div>
  {f"<h2>⚠ Problemas e información ({sum(conteo[n] for n in (Risk.ALTO, Risk.MEDIO, Risk.BAJO, Risk.INFO))})</h2>{tarjetas_riesgo}" if tarjetas_riesgo else ""}
  {f"<h2>✅ Buenas prácticas confirmadas ({conteo[Risk.OK]})</h2>{tarjetas_ok}" if tarjetas_ok else ""}
  <footer>Generado por WebVulnScanner 2.0 · Auditoría pasiva · Uso académico y ético.
  Solo analice sitios propios o con autorización expresa.</footer>
</div></body></html>"""
