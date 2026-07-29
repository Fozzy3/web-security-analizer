"""Fase N: descubrimiento de superficie API (OpenAPI/Swagger + GraphQL introspection)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import api_discovery
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200):
    return HttpResponse("http://x/", "http", status, {}, body)


_OPENAPI = '{"openapi":"3.0.0","paths":{"/users":{},"/orders":{},"/login":{}}}'
_INTROSPECCION = '{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}'


def test_openapi_expuesto_se_reporta(monkeypatch):
    def fake(d, ruta="/", **k):
        return _resp(_OPENAPI) if ruta == "/openapi.json" else _resp(status=404)

    monkeypatch.setattr(api_discovery, "fetch", fake)
    monkeypatch.setattr(api_discovery, "request", lambda *a, **k: _resp(status=404))
    fs = api_discovery.analizar("ej.com")
    assert any("API" in f.hallazgo or "OpenAPI" in f.hallazgo for f in fs)
    # documenta la cantidad de endpoints (3)
    assert any("3" in (f.descripcion + f.hallazgo) for f in fs)


def test_sin_openapi_ni_graphql_no_reporta(monkeypatch):
    monkeypatch.setattr(api_discovery, "fetch", lambda d, ruta="/", **k: _resp(status=404))
    monkeypatch.setattr(api_discovery, "request", lambda *a, **k: _resp(status=404))
    assert api_discovery.analizar("ej.com") == []


def test_graphql_introspeccion_abierta_es_medio(monkeypatch):
    monkeypatch.setattr(api_discovery, "fetch", lambda d, ruta="/", **k: _resp(status=404))

    def fake_req(d, ruta="/", **k):
        return _resp(_INTROSPECCION) if "graphql" in ruta else _resp(status=404)

    monkeypatch.setattr(api_discovery, "request", fake_req)
    fs = api_discovery.analizar("ej.com")
    assert any(f.riesgo is Risk.MEDIO and "introspec" in f.hallazgo.lower() for f in fs)


def test_graphql_deshabilitada_no_reporta(monkeypatch):
    monkeypatch.setattr(api_discovery, "fetch", lambda d, ruta="/", **k: _resp(status=404))
    monkeypatch.setattr(
        api_discovery, "request", lambda d, ruta="/", **k: _resp('{"errors":["introspection disabled"]}')
    )
    assert api_discovery.analizar("ej.com") == []
