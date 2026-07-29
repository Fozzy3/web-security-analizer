"""Fase Q: control de acceso — IDOR/BOLA + forced browsing (activo, gateado)."""

from __future__ import annotations

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Risk
from webvulnscanner.modules import access_control as ac
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200):
    return HttpResponse("http://x/", "http", status, {}, body)


# ── helpers puros ────────────────────────────────────────────


def test_segmento_numerico():
    assert ac._segmento_numerico("/api/user/1001") == ("/api/user/", "1001", "")
    assert ac._segmento_numerico("/item?id=5") == ("/item?id=", "5", "")
    assert ac._segmento_numerico("/sin/numeros") is None


def test_vecino():
    assert ac._vecino("1001") == "1002"


# ── IDOR ─────────────────────────────────────────────────────


def test_idor_objeto_ajeno_accesible_es_alto(monkeypatch):
    def fake(d, ruta="/", **k):
        if ruta == "/api/user/1001":
            return _resp("datos de Alice")
        if ruta == "/api/user/1002":
            return _resp("datos de Bob")  # objeto ajeno, contenido distinto
        return _resp(status=404)

    monkeypatch.setattr(ac, "request", fake)
    c = Crawl()
    c.urls = {"https://ej.com/api/user/1001"}
    fs = ac.analizar("ej.com", c)
    assert any("IDOR" in f.hallazgo and f.riesgo is Risk.ALTO for f in fs)


def test_idor_denegado_no_reporta(monkeypatch):
    def fake(d, ruta="/", **k):
        if ruta == "/api/user/1001":
            return _resp("datos de Alice")
        return _resp(status=403)  # el vecino está protegido

    monkeypatch.setattr(ac, "request", fake)
    c = Crawl()
    c.urls = {"https://ej.com/api/user/1001"}
    assert ac.analizar("ej.com", c) == []


def test_idor_mismo_contenido_no_reporta(monkeypatch):
    # Si el vecino devuelve lo mismo (p.ej. página genérica), no es IDOR.
    monkeypatch.setattr(ac, "request", lambda d, ruta="/", **k: _resp("misma página"))
    c = Crawl()
    c.urls = {"https://ej.com/api/user/1001"}
    assert ac.analizar("ej.com", c) == []


# ── forced browsing ──────────────────────────────────────────


def test_forced_browsing_panel_sin_sesion_es_alto(monkeypatch):
    def fake(d, ruta="/", *, sin_sesion=False, **k):
        # el panel admin responde 200 SIN sesión
        if ruta == "/admin" and sin_sesion:
            return _resp("<h1>Panel de administración</h1>")
        return _resp(status=404)

    monkeypatch.setattr(ac, "request", fake)
    fs = ac.analizar("ej.com", Crawl())
    assert any("administra" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


def test_forced_browsing_protegido_no_reporta(monkeypatch):
    monkeypatch.setattr(ac, "request", lambda d, ruta="/", **k: _resp(status=403))
    assert ac.analizar("ej.com", Crawl()) == []
