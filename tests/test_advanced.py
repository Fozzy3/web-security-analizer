"""Tests de los módulos avanzados nativos (Fases F-K)."""

import webvulnscanner.enrich as enrich
from webvulnscanner import owasp
from webvulnscanner.models import Finding, Risk
from webvulnscanner.modules import external, retire_js, secrets, webchecks
from webvulnscanner.net import HttpResponse


def _resp(body="", esquema="https"):
    return HttpResponse(f"{esquema}://x/", esquema, 200, {}, body)


# ── retire.js ─────────────────────────────────────────────────
def test_retirejs_detecta_jquery_viejo():
    fs = retire_js.analizar_scripts({"http://x/js/jquery-1.8.2.min.js"})
    assert fs and fs[0].owasp == "A06:2021" and "jquery" in fs[0].hallazgo.lower()


def test_retirejs_ignora_version_segura():
    assert retire_js.analizar_scripts({"http://x/js/jquery-3.6.0.min.js"}) == []


# ── secrets ───────────────────────────────────────────────────
def test_secrets_detecta_aws_y_google():
    txt = 'var k="AKIAIOSFODNN7EXAMPLE"; var g="AIzaSyD-1234567890abcdefghijklmnopqrstuv";'
    hallados = {t for t, _, _ in secrets.escanear_texto(txt)}
    assert "AWS Access Key" in hallados
    assert "Google API Key" in hallados


def test_secrets_sin_falsos_positivos():
    assert secrets.escanear_texto("solo texto normal sin claves aquí") == []


# ── webchecks ─────────────────────────────────────────────────
def test_webchecks_mixed_content():
    fs = webchecks.analizar(_resp('<img src="http://cdn.com/a.png">', esquema="https"))
    assert any("Mixed content" in f.hallazgo for f in fs)


def test_webchecks_sri_ausente():
    fs = webchecks.analizar(_resp('<script src="https://cdn.com/lib.js"></script>', esquema="https"))
    assert any("Subresource Integrity" in f.hallazgo for f in fs)


def test_webchecks_password_sobre_http():
    fs = webchecks.analizar(_resp('<input type="password">', esquema="http"))
    assert any(f.riesgo == Risk.ALTO for f in fs)


# ── owasp ─────────────────────────────────────────────────────
def test_owasp_etiqueta_por_modulo():
    fs = [Finding("TLS/HTTPS", "h", Risk.ALTO, "d"), Finding("Inyección", "h", Risk.ALTO, "d")]
    owasp.etiquetar(fs)
    assert fs[0].owasp == "A02:2021"
    assert fs[1].owasp == "A03:2021"


def test_owasp_takeover_es_a01():
    fs = [Finding("Subdominios", "Posible subdomain takeover: x", Risk.ALTO, "d")]
    owasp.etiquetar(fs)
    assert fs[0].owasp == "A01:2021"


# ── enrich (EPSS + KEV) ───────────────────────────────────────
def test_enrich_marca_kev_como_alto(monkeypatch):
    monkeypatch.setattr(enrich, "cves_kev", lambda: {"CVE-2021-23017"})
    monkeypatch.setattr(enrich, "epss_scores", lambda ids: {"CVE-2021-23017": 0.42})
    fs = [Finding("CVE", "CVE-2021-23017 — nginx 1.18.0", Risk.MEDIO, "desc")]
    enrich.enriquecer(fs)
    assert fs[0].riesgo == Risk.ALTO  # KEV eleva a alto
    assert "KEV" in fs[0].descripcion and "EPSS" in fs[0].descripcion


def test_enrich_sin_cves_no_hace_nada(monkeypatch):
    llamado = {"kev": False}
    monkeypatch.setattr(enrich, "cves_kev", lambda: llamado.update(kev=True) or set())
    fs = [Finding("Headers HTTP", "CSP ausente", Risk.ALTO, "d")]
    enrich.enriquecer(fs)
    assert llamado["kev"] is False  # no consultó nada


# ── external: ruta de omisión (binario ausente) ───────────────
def test_external_omite_si_falta_binario(monkeypatch):
    import webvulnscanner.tools as tools

    monkeypatch.setattr(tools, "disponible", lambda b: False)
    assert external.nuclei("x.com") == []
    assert external.nmap("1.2.3.4") == []
    assert external.wpscan("x.com") == []
    assert external.subfinder("x.com") == []
