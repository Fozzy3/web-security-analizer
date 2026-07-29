"""Caracterización del etiquetado OWASP Top 10 **2025** (owasp.py)."""

from __future__ import annotations

import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.owasp import CATEGORIAS, categoria, etiquetar

_ID_2025 = re.compile(r"^A(0[1-9]|10):2025$")


def _f(modulo="Test", hallazgo="hallazgo", owasp=None):
    return Finding(modulo, hallazgo, Risk.INFO, "desc", owasp=owasp)


# ── catálogo ─────────────────────────────────────────────────


def test_catalogo_2025_tiene_diez_entradas_todas_2025():
    assert len(CATEGORIAS) == 10
    assert all(_ID_2025.match(cid) for cid in CATEGORIAS)


# ── remapeo 2021 → 2025 ──────────────────────────────────────


def test_etiquetar_remapea_supply_chain_a06_2021_a_a03_2025():
    f = _f(owasp="A06:2021")
    etiquetar([f])
    assert f.owasp == "A03:2025"


def test_etiquetar_remapea_ssrf_a10_2021_a_a01_2025():
    f = _f(owasp="A10:2021")
    etiquetar([f])
    assert f.owasp == "A01:2025"


# ── overrides por contenido ──────────────────────────────────


def test_override_stack_trace_es_a10_2025():
    f = _f(hallazgo="Se expuso un stack trace en la respuesta", owasp="A05:2021")
    etiquetar([f])
    assert f.owasp == "A10:2025"


def test_override_modo_debug_es_a10_2025():
    f = _f(hallazgo="Aplicación en modo debug", owasp="A05:2021")
    etiquetar([f])
    assert f.owasp == "A10:2025"


def test_override_takeover_es_a01_2025():
    f = _f(modulo="Subdominios", hallazgo="Subdomain takeover posible", owasp="A02:2021")
    etiquetar([f])
    assert f.owasp == "A01:2025"


# ── fallback por módulo ──────────────────────────────────────


def test_sin_owasp_cae_al_mapeo_por_modulo():
    f = _f(modulo="Inyección", hallazgo="parámetro reflejado")
    assert f.owasp is None
    etiquetar([f])
    assert f.owasp == "A05:2025"


def test_categoria_sin_owasp_ni_modulo_conocido_es_none():
    assert categoria(_f(modulo="Desconocido", hallazgo="algo")) is None


# ── API Security Top 10 2023 ─────────────────────────────────

_ID_API = re.compile(r"^API(0?[1-9]|10):2023$")


def test_etiquetar_asigna_api_por_modulo():
    casos = {
        "Control de Acceso": "API1:2023",
        "Autenticación": "API2:2023",
        "JWT": "API2:2023",
        "SSRF": "API7:2023",
        "Rate Limiting": "API4:2023",
        "Cloud": "API8:2023",
        "API": "API9:2023",
    }
    for modulo, esperado in casos.items():
        f = _f(modulo=modulo, hallazgo="algo")
        etiquetar([f])
        assert f.api == esperado, f"{modulo} → {f.api}, esperado {esperado}"


def test_api_override_forced_browsing_es_api5():
    f = _f(modulo="Control de Acceso", hallazgo="Forced browsing: /admin accesible sin sesión")
    etiquetar([f])
    assert f.api == "API5:2023"


def test_modulo_no_api_no_recibe_tag():
    f = _f(modulo="TLS/HTTPS", hallazgo="protocolo obsoleto")
    etiquetar([f])
    assert f.api is None


def test_api_cobertura_al_menos_siete_categorias_distintas():
    modulos = ["Control de Acceso", "Autenticación", "SSRF", "Rate Limiting", "Cloud", "API", "API Fuzzing"]
    fs = [_f(modulo=m, hallazgo="x") for m in modulos]
    fs.append(_f(modulo="Control de Acceso", hallazgo="Forced browsing sin sesión"))
    etiquetar(fs)
    distintas = {f.api for f in fs if f.api}
    assert all(_ID_API.match(a) for a in distintas)
    assert len(distintas) >= 7
