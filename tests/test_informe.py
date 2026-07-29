"""Tests del generador de informe de 3 pestañas (data-driven desde ScanResult)."""

from __future__ import annotations

import re

from webvulnscanner import informe
from webvulnscanner.models import Finding, Risk, ScanResult


def _result():
    return ScanResult(
        "ej.com",
        ip="1.2.3.4",
        servidor="nginx/1.18.0",
        findings=[
            Finding(
                "Inyección",
                "Posible XSS reflejado en / (parámetro 'q', GET)",
                Risk.ALTO,
                "El parámetro se refleja sin codificar.",
                owasp="A05:2025",
                cwe="CWE-79",
                cvss={"vector": "x", "score": 6.1},
                referencia="https://ref",
            ),
            Finding("Headers HTTP", "HSTS presente", Risk.OK, "Bien configurado."),
            Finding("Fingerprint", "Tecnologías", Risk.INFO, "detectado", evidencia="nginx, WordPress"),
        ],
    )


def test_genera_html_valido_con_3_pestanas():
    h = informe.generar(_result(), timestamp="2026-01-01 00:00:00")
    assert h.startswith("<!doctype html>")
    for x in ("v-inf", "v-int", "v-mod", "t-inf", "t-int", "t-mod"):
        assert x in h
    # balance de divs
    assert len(re.findall(r"<div\b", h)) == len(re.findall(r"</div>", h))


def test_incluye_datos_del_escaneo():
    h = informe.generar(_result(), timestamp="t")
    assert "ej.com" in h and "1.2.3.4" in h
    assert "XSS reflejado" in h  # hallazgo
    assert "CWE-79" in h and "6.1" in h  # detalle técnico
    assert "nginx, WordPress" in h  # inteligencia (tecnologías)


def test_ordena_por_severidad_y_cuenta():
    h = informe.generar(_result(), timestamp="t")
    # el crítico (XSS) aparece antes que el correcto (HSTS)
    assert h.index("XSS reflejado") < h.index("HSTS presente")
    assert "1 críticos" in h and "1 correctos" in h


def test_escapa_html_malicioso():
    r = ScanResult("ej.com", findings=[Finding("X", "<script>alert(1)</script>", Risk.BAJO, "d")])
    h = informe.generar(r, timestamp="t")
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h


def test_pestana_modulos_lista_pasivos_y_activos():
    h = informe.generar(_result(), timestamp="t")
    assert "Módulos pasivos" in h and "Módulos activos" in h
    assert "Control de acceso" in h and "TLS profundo (sslyze)" in h
