"""Fase O: clasificación de hallazgos (CWE + CVSS v3.1 nativo)."""

from __future__ import annotations

from webvulnscanner import classify
from webvulnscanner.models import Finding, Risk

# ── fórmula CVSS v3.1 (vectores oficiales conocidos) ─────────


def test_cvss_score_7_5():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert classify.cvss_base(v) == 7.5


def test_cvss_score_9_8_critico():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert classify.cvss_base(v) == 9.8


def test_cvss_scope_changed():
    # XSS reflejado típico: scope changed, impactos bajos → 6.1
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert classify.cvss_base(v) == 6.1


def test_cvss_sin_impacto_es_cero():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert classify.cvss_base(v) == 0.0


# ── clasificación de hallazgos ───────────────────────────────


def test_clasifica_xss_con_cwe_79():
    fs = [Finding("Inyección", "Posible XSS reflejado en / (parámetro 'q', GET)", Risk.ALTO, "d")]
    classify.clasificar(fs)
    assert fs[0].cwe == "CWE-79"
    assert fs[0].cvss is not None and fs[0].cvss["score"] >= 6.0


def test_clasifica_sqli_con_cwe_89():
    fs = [Finding("Inyección", "Posible SQL injection en / (parámetro 'id', GET)", Risk.ALTO, "d")]
    classify.clasificar(fs)
    assert fs[0].cwe == "CWE-89"


def test_hallazgo_sin_mapeo_queda_sin_cwe():
    fs = [Finding("Reconocimiento", "IP resuelta", Risk.INFO, "d")]
    classify.clasificar(fs)
    assert fs[0].cwe is None and fs[0].cvss is None
