"""Fase U: manejo de condiciones excepcionales (A10:2025, activo suave)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import error_audit
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200, headers=None):
    return HttpResponse("http://x/", "http", status, headers or {}, body)


def test_detecta_stack_trace():
    assert error_audit._es_stack_trace('Traceback (most recent call last):\n  File "x.py", line 3')
    assert error_audit._es_stack_trace("at java.lang.String.charAt(String.java:100)")
    assert not error_audit._es_stack_trace("página de error genérica 500")


def test_detecta_modo_debug():
    assert error_audit._es_debug("Werkzeug Debugger: pin required")
    assert not error_audit._es_debug("<html>ok</html>")


def test_stack_trace_expuesto_es_medio(monkeypatch):
    monkeypatch.setattr(
        error_audit,
        "request",
        lambda d, ruta="/", **k: _resp('Traceback (most recent call last): File "app.py", line 42', 500),
    )
    fs = error_audit.analizar("ej.com")
    assert any("error" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_modo_debug_es_alto(monkeypatch):
    monkeypatch.setattr(
        error_audit, "request", lambda d, ruta="/", **k: _resp("Werkzeug Debugger console", 500)
    )
    fs = error_audit.analizar("ej.com")
    assert any("debug" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


def test_error_limpio_no_reporta(monkeypatch):
    monkeypatch.setattr(error_audit, "request", lambda d, ruta="/", **k: _resp("Error 500", 500))
    assert error_audit.analizar("ej.com") == []


def test_detecta_debug_por_headers():
    assert error_audit._debug_por_headers(_resp(headers={"x-debug": "1"})) == "x-debug"
    assert error_audit._debug_por_headers(_resp(headers={"x-debug-token": "abc"})) == "x-debug-token"
    assert (
        error_audit._debug_por_headers(_resp(headers={"x-debug-token-link": "http://x/_profiler/abc"}))
        == "x-debug-token-link"
    )
    assert error_audit._debug_por_headers(_resp(headers={"content-type": "text/html"})) is None
    assert error_audit._debug_por_headers(_resp()) is None


def test_header_x_debug_es_modo_debug_alto(monkeypatch):
    monkeypatch.setattr(
        error_audit,
        "request",
        lambda d, ruta="/", **k: _resp("Error 500", 500, {"x-debug": "1"}),
    )
    fs = error_audit.analizar("ej.com")
    assert any("debug" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


def test_header_symfony_token_es_modo_debug_alto(monkeypatch):
    monkeypatch.setattr(
        error_audit,
        "request",
        lambda d, ruta="/", **k: _resp("<html>ok</html>", 200, {"x-debug-token": "abc123"}),
    )
    fs = error_audit.analizar("ej.com")
    assert any("debug" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


def test_respuesta_sin_header_ni_traza_no_reporta(monkeypatch):
    monkeypatch.setattr(
        error_audit,
        "request",
        lambda d, ruta="/", **k: _resp("Error 500", 500, {"content-type": "text/html"}),
    )
    assert error_audit.analizar("ej.com") == []
