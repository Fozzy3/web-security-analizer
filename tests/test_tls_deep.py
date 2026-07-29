"""Tests del análisis TLS profundo (sslyze). Se prueba el mapeo puro."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import tls_deep


def test_mapea_vulnerabilidades_criticas():
    fs = tls_deep._mapear({"heartbleed": True, "sslv3": True, "robot": False})
    hallazgos = {f.hallazgo for f in fs}
    assert "Vulnerable a Heartbleed" in hallazgos
    assert "Acepta SSLv3" in hallazgos
    assert all(f.riesgo is Risk.ALTO for f in fs)


def test_protocolos_obsoletos_son_medio():
    fs = tls_deep._mapear({"tls10": True, "tls11": True})
    assert fs and all(f.riesgo is Risk.MEDIO for f in fs)


def test_todo_seguro_no_reporta():
    fs = tls_deep._mapear({"heartbleed": False, "robot": False, "sslv2": False, "tls10": False})
    assert fs == []


def test_analizar_sin_sslyze_devuelve_vacio(monkeypatch):
    monkeypatch.setattr(tls_deep, "_SSLYZE", False)
    assert tls_deep.analizar("ej.com") == []
