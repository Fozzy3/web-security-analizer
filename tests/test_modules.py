"""Tests de los `analizar` que operan sobre un HttpResponse (sin red real)."""

import webvulnscanner.modules.ports as ports
from webvulnscanner.models import Risk
from webvulnscanner.modules import fingerprint, headers, waf
from webvulnscanner.net import HttpResponse


def _resp(hdrs=None, body="", status=200):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (hdrs or {}).items()}, body)


# ── headers.analizar ──────────────────────────────────────────
def test_headers_todo_ausente_marca_csp_alto():
    fs = headers.analizar(_resp())
    csp = [f for f in fs if "Content-Security-Policy ausente" in f.hallazgo]
    assert csp and csp[0].riesgo == Risk.ALTO


def test_headers_csp_robusta_es_ok():
    fs = headers.analizar(_resp({"Content-Security-Policy": "default-src 'self'; object-src 'none'"}))
    assert any(f.riesgo == Risk.OK and "CSP" in f.hallazgo for f in fs)


def test_headers_respuesta_none():
    fs = headers.analizar(None)
    assert len(fs) == 1 and fs[0].riesgo == Risk.INFO


# ── waf.analizar ──────────────────────────────────────────────
def test_waf_cloudflare():
    fs = waf.analizar(_resp({"server": "cloudflare", "cf-ray": "x"}))
    assert any("Cloudflare" in f.hallazgo for f in fs)


def test_waf_none_no_findings():
    assert waf.analizar(None) == []


# ── fingerprint.analizar ──────────────────────────────────────
def test_fingerprint_wordpress_con_version_es_medio():
    fs = fingerprint.analizar(_resp(body='<meta name="generator" content="WordPress 5.8.1">'))
    assert fs and fs[0].riesgo == Risk.MEDIO


# ── ports.analizar (con red simulada) ─────────────────────────
def test_ports_con_puertos_abiertos(monkeypatch):
    monkeypatch.setattr(ports, "_escanear", lambda ip, p, t: p in (22, 443))
    monkeypatch.setattr(ports, "leer_banner", lambda *a, **k: "OpenSSH_8.2")
    fs = ports.analizar("1.2.3.4")
    abiertos = {f.hallazgo for f in fs}
    assert any("22/TCP" in h for h in abiertos)
    assert any("443/TCP" in h for h in abiertos)


def test_ports_sin_abiertos(monkeypatch):
    monkeypatch.setattr(ports, "_escanear", lambda ip, p, t: False)
    fs = ports.analizar("1.2.3.4")
    assert len(fs) == 1 and fs[0].riesgo == Risk.INFO
