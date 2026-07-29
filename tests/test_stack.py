"""Tests del módulo stack (Wappalyzer + CVE multi-componente), con la lib simulada."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import stack
from webvulnscanner.net import HttpResponse


def _resp():
    return HttpResponse("https://ej.com/", "https", 200, {"server": "nginx/1.18.0"}, "<html></html>")


def test_resumen_de_stack_y_cve_por_componente(monkeypatch):
    # Wappalyzer detecta WordPress 6.5 y jQuery 3.7.1.
    monkeypatch.setattr(
        stack,
        "detectar",
        lambda r: {
            "WordPress": {"versions": ["6.5"], "categories": ["CMS"]},
            "jQuery": {"versions": ["3.7.1"], "categories": ["JS"]},
            "PHP": {"versions": [], "categories": ["Lang"]},
        },
    )

    # CVE simulado: WordPress 6.5 tiene un CVE alto.
    def fake_nvd(prod, ver, **k):
        if prod == "wordpress":
            return [{"id": "CVE-2024-9999", "score": 8.1, "severidad": "HIGH", "resumen": "XSS en WP"}]
        return []

    monkeypatch.setattr(stack.cve, "consultar_nvd", fake_nvd)
    fs = stack.analizar("ej.com", _resp())

    resumen = [f for f in fs if f.modulo == "Stack"]
    assert resumen and "WordPress 6.5" in resumen[0].evidencia
    cves = [f for f in fs if f.modulo == "CVE"]
    assert cves and cves[0].riesgo is Risk.ALTO and "CVE-2024-9999" in cves[0].hallazgo


def test_sin_deteccion_no_reporta(monkeypatch):
    monkeypatch.setattr(stack, "detectar", lambda r: {})
    assert stack.analizar("ej.com", _resp()) == []


def test_sin_respuesta_no_falla():
    assert stack.analizar("ej.com", None) == []
