"""Fase V: consumo de recursos / rate-limit (API4:2023, activo suave)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import rate_limit
from webvulnscanner.net import HttpResponse


def _resp(status=200, headers=None):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (headers or {}).items()}, "")


def test_sin_rate_limit_es_bajo(monkeypatch):
    monkeypatch.setattr(rate_limit, "request", lambda d, ruta="/", **k: _resp(200))
    fs = rate_limit.analizar("ej.com", burst=8)
    assert any("rate" in f.hallazgo.lower() and f.riesgo is Risk.BAJO for f in fs)


def test_con_429_no_reporta(monkeypatch):
    monkeypatch.setattr(rate_limit, "request", lambda d, ruta="/", **k: _resp(429))
    assert rate_limit.analizar("ej.com", burst=8) == []


def test_con_header_ratelimit_no_reporta(monkeypatch):
    monkeypatch.setattr(
        rate_limit, "request", lambda d, ruta="/", **k: _resp(200, {"X-RateLimit-Remaining": "10"})
    )
    assert rate_limit.analizar("ej.com", burst=8) == []


def test_respeta_burst(monkeypatch):
    llamadas = []
    monkeypatch.setattr(rate_limit, "request", lambda d, ruta="/", **k: (llamadas.append(1), _resp(200))[1])
    rate_limit.analizar("ej.com", burst=5)
    assert len(llamadas) == 5
