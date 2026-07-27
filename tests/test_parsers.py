"""Tests de la lógica pura de parsing (sin red)."""

from webvulnscanner.models import Risk
from webvulnscanner.modules import fingerprint, headers, recon, waf
from webvulnscanner.net import HttpResponse


def _resp(hdrs=None, body="", status=200):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (hdrs or {}).items()}, body)


# ── headers: CSP ──────────────────────────────────────────────
def test_csp_detecta_unsafe_inline():
    probs = headers.evaluar_csp("default-src 'self'; script-src 'unsafe-inline'")
    assert any(n == Risk.ALTO and "unsafe-inline" in m for n, m in probs)


def test_csp_wildcard_es_alto():
    probs = headers.evaluar_csp("default-src *")
    assert any(n == Risk.ALTO for n, _ in probs)


def test_csp_robusta_sin_problemas():
    assert headers.evaluar_csp("default-src 'self'; script-src 'self'; object-src 'none'") == []


# ── headers: HSTS ─────────────────────────────────────────────
def test_hsts_max_age_bajo():
    probs = headers.evaluar_hsts("max-age=3600")
    assert any(n == Risk.BAJO for n, _ in probs)  # < 6 meses
    assert any("includeSubDomains" in m or "includesubdomains" in m.lower() for _, m in probs)


def test_hsts_robusto():
    assert headers.evaluar_hsts("max-age=31536000; includeSubDomains; preload") == []


# ── recon: extracción de versión ──────────────────────────────
def test_extraer_producto_version():
    assert recon.extraer_producto_version("Apache/2.4.29 (Ubuntu)") == ("apache", "2.4.29")
    assert recon.extraer_producto_version("nginx/1.18.0") == ("nginx", "1.18.0")
    assert recon.extraer_producto_version("cloudflare") is None


# ── waf ───────────────────────────────────────────────────────
def test_waf_detecta_cloudflare():
    assert "Cloudflare" in waf.detectar({"server": "cloudflare", "cf-ray": "abc"})


def test_waf_sin_firmas():
    assert waf.detectar({"server": "Apache"}) == []


# ── fingerprint ───────────────────────────────────────────────
def test_fingerprint_wordpress_por_body():
    r = _resp(body='<link href="/wp-content/themes/x/style.css">')
    assert "WordPress" in fingerprint.detectar(r)


def test_fingerprint_generator_con_version():
    r = _resp(body='<meta name="generator" content="WordPress 5.8.1" />')
    techs = fingerprint.detectar(r)
    assert any("5.8.1" in k or "5.8.1" in v for k, v in techs.items())
