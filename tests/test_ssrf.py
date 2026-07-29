"""Fase S: SSRF activo + Host Header Injection (activo, gateado)."""

from __future__ import annotations

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Risk
from webvulnscanner.modules import ssrf
from webvulnscanner.net import HttpResponse


def _resp(body="", headers=None, status=200):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (headers or {}).items()}, body)


def test_confirma_ssrf_por_firma_metadata():
    assert ssrf._confirma_ssrf("ami-id: ami-123\ninstance-id: i-abc")
    assert not ssrf._confirma_ssrf("<html>página normal</html>")


def test_ssrf_por_parametro_es_alto(monkeypatch):
    def fake(d, ruta="/", **k):
        if "169.254.169.254" in ruta:
            return _resp("instance-id: i-0abc meta-data")
        return _resp("ok")

    monkeypatch.setattr(ssrf, "request", fake)
    fs = ssrf.analizar("ej.com", Crawl())
    assert any("SSRF" in f.hallazgo and f.riesgo is Risk.ALTO for f in fs)


def test_host_header_reflejado_es_medio(monkeypatch):
    def fake(d, ruta="/", *, headers=None, **k):
        marc = (headers or {}).get("Host", "")
        return _resp(f'<a href="https://{marc}/reset">reset</a>')

    monkeypatch.setattr(ssrf, "request", fake)
    fs = ssrf.analizar("ej.com", Crawl())
    assert any("host header" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_cache_poisoning_cuando_cacheable(monkeypatch):
    def fake(d, ruta="/", *, headers=None, **k):
        marc = (headers or {}).get("X-Forwarded-Host", "")
        return _resp(f"host={marc}", headers={"Cache-Control": "public, max-age=60"})

    monkeypatch.setattr(ssrf, "request", fake)
    fs = ssrf.analizar("ej.com", Crawl())
    assert any("cache" in f.hallazgo.lower() for f in fs)


def test_sin_ssrf_ni_reflejo_no_reporta(monkeypatch):
    monkeypatch.setattr(ssrf, "request", lambda d, ruta="/", **k: _resp("contenido inocuo"))
    assert ssrf.analizar("ej.com", Crawl()) == []
