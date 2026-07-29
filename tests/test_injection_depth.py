"""Fase M: inyección profunda (form/POST, por-parámetro, LFI/SSTI/CRLF/cmdi, blind SQLi).

Red simulada: se parchean `active.fetch` (GET) y `active.request` (POST).
"""

from __future__ import annotations

import webvulnscanner.modules.active as active
from webvulnscanner.crawler import Crawl, Form
from webvulnscanner.models import Risk
from webvulnscanner.net import HttpResponse


def _resp(body="", headers=None, status=200):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (headers or {}).items()}, body)


# ── helpers puros de confirmación ────────────────────────────


def test_confirma_lfi_por_firma_passwd():
    assert active._confirma_lfi("root:x:0:0:root:/root:/bin/bash\n")
    assert not active._confirma_lfi("<html>página normal</html>")


def test_confirma_ssti_solo_si_evalua():
    assert active._confirma_ssti(f"resultado: {active._SSTI_RESULT} listo")
    # el payload literal sin evaluar NO cuenta como confirmación
    assert not active._confirma_ssti("plantilla 113*131 sin procesar")


def test_confirma_crlf_por_header_inyectado():
    assert active._confirma_crlf({active._CRLF_HEADER: active._MARCADOR})
    assert not active._confirma_crlf({"content-type": "text/html"})


def test_es_retardo_requiere_dos_confirmaciones():
    assert active._es_retardo(0.1, 3.2, 3.1, umbral=2.0)
    # la segunda medición no supera el umbral → no es retardo consistente
    assert not active._es_retardo(0.1, 3.2, 0.2, umbral=2.0)


# ── puntos de inyección (query + forms) ──────────────────────


def test_puntos_incluye_query_y_forms():
    c = Crawl()
    c.params = {"/buscar": {"q"}}
    c.forms = [Form(action="/login", method="post", inputs=["user", "pass"])]
    pts = active._puntos_inyeccion(c)
    assert any(p.ruta == "/buscar" and p.param == "q" and p.metodo == "GET" for p in pts)
    login = [p for p in pts if p.ruta == "/login"]
    assert {p.param for p in login} == {"user", "pass"}
    assert all(p.metodo == "POST" for p in login)


def test_puntos_fallback_sin_crawl():
    pts = active._puntos_inyeccion(None)
    assert pts and all(p.metodo == "GET" for p in pts)


# ── inyección: comportamiento ────────────────────────────────


def test_xss_por_parametro_reporta_todos(monkeypatch):
    """No corta al primer hallazgo: dos parámetros reflejados → dos hallazgos."""
    c = Crawl()
    c.params = {"/": {"a", "b"}}
    monkeypatch.setattr(active, "fetch", lambda d, ruta="/", **k: _resp(body=f"{active._XSS} fin"))
    monkeypatch.setattr(active, "request", lambda *a, **k: _resp(body="ok"))
    fs = active.analizar_inyeccion("ej.com", c)
    xss = [f for f in fs if "XSS" in f.hallazgo]
    assert {f.referencia for f in xss} == {"/?a=", "/?b="}


def test_xss_via_post_form(monkeypatch):
    c = Crawl()
    c.forms = [Form(action="/buscar", method="post", inputs=["q"])]

    def fake_request(d, ruta="/", *, method="GET", data=None, **k):
        val = (data or {}).get("q", "")
        return _resp(body=f"echo {val} fin")

    monkeypatch.setattr(active, "request", fake_request)
    monkeypatch.setattr(active, "fetch", lambda *a, **k: _resp(body="ok"))
    fs = active.analizar_inyeccion("ej.com", c)
    xss = [f for f in fs if "XSS" in f.hallazgo]
    assert xss and "POST" in xss[0].hallazgo


def test_lfi_detectado(monkeypatch):
    c = Crawl()
    c.params = {"/": {"file"}}
    monkeypatch.setattr(
        active, "fetch", lambda d, ruta="/", **k: _resp(body="root:x:0:0:root:/root:/bin/bash")
    )
    monkeypatch.setattr(active, "request", lambda *a, **k: _resp(body="ok"))
    fs = active.analizar_inyeccion("ej.com", c)
    assert any("LFI" in f.hallazgo and f.riesgo is Risk.ALTO for f in fs)


def test_ssti_detectado(monkeypatch):
    c = Crawl()
    c.params = {"/": {"tpl"}}
    monkeypatch.setattr(active, "fetch", lambda d, ruta="/", **k: _resp(body=f"out {active._SSTI_RESULT}"))
    monkeypatch.setattr(active, "request", lambda *a, **k: _resp(body="ok"))
    fs = active.analizar_inyeccion("ej.com", c)
    assert any("SSTI" in f.hallazgo for f in fs)


def test_sin_vulnerabilidad_no_reporta(monkeypatch):
    c = Crawl()
    c.params = {"/": {"x"}}
    monkeypatch.setattr(active, "fetch", lambda d, ruta="/", **k: _resp(body="contenido inocuo"))
    monkeypatch.setattr(active, "request", lambda *a, **k: _resp(body="ok"))
    assert active.analizar_inyeccion("ej.com", c) == []
