"""Tests de los módulos activos (Fase D) con red simulada."""

import webvulnscanner.modules.active as active
from webvulnscanner.models import Risk
from webvulnscanner.net import HttpResponse


def _resp(hdrs=None, body="", status=200):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (hdrs or {}).items()}, body)


# ── cookies ───────────────────────────────────────────────────
def test_cookies_sin_flags_reporta_tres():
    fs = active.analizar_cookies(_resp({"Set-Cookie": "sid=abc"}))
    tipos = {f.hallazgo for f in fs}
    assert any("Secure" in t for t in tipos)
    assert any("HttpOnly" in t for t in tipos)
    assert any("SameSite" in t for t in tipos)


def test_cookies_completas_no_reporta():
    fs = active.analizar_cookies(_resp({"Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Strict"}))
    assert fs == []


# ── CORS ──────────────────────────────────────────────────────
def test_cors_refleja_origin_con_credenciales_es_alto(monkeypatch):
    monkeypatch.setattr(
        active,
        "fetch",
        lambda d, r="/", **k: _resp(
            {
                "Access-Control-Allow-Origin": "https://evil.example",
                "Access-Control-Allow-Credentials": "true",
            }
        ),
    )
    fs = active.analizar_cors("ej.com")
    assert fs and fs[0].riesgo == Risk.ALTO


def test_cors_wildcard_es_medio(monkeypatch):
    monkeypatch.setattr(active, "fetch", lambda d, r="/", **k: _resp({"Access-Control-Allow-Origin": "*"}))
    fs = active.analizar_cors("ej.com")
    assert fs and fs[0].riesgo == Risk.MEDIO


# ── inyección ─────────────────────────────────────────────────
def test_xss_reflejado_detectado(monkeypatch):
    def fake(d, ruta="/", **k):
        # refleja el payload crudo
        return _resp(body=f'echo {active._MARCADOR}"<x> fin')

    monkeypatch.setattr(active, "fetch", fake)
    fs = active.analizar_inyeccion("ej.com")
    assert any("XSS" in f.hallazgo for f in fs)


def test_sqli_error_detectado(monkeypatch):
    def fake(d, ruta="/", **k):
        if "id=1" in ruta:
            return _resp(body="You have an error in your SQL syntax near '1''")
        return _resp(body="ok")

    monkeypatch.setattr(active, "fetch", fake)
    fs = active.analizar_inyeccion("ej.com")
    assert any("SQL" in f.hallazgo for f in fs)


# ── fuzzing ───────────────────────────────────────────────────
def test_fuzzing_reporta_rutas_200(monkeypatch):
    monkeypatch.setattr(
        active, "fetch", lambda d, r="/", **k: _resp(status=200) if r == "/admin" else _resp(status=404)
    )
    fs = active.analizar_fuzzing("ej.com")
    assert any("/admin" in f.hallazgo for f in fs)
