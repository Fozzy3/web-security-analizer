"""Fase O: mapeo de hallazgos a controles de cumplimiento (PCI/ISO/NIST)."""

from __future__ import annotations

from webvulnscanner import compliance
from webvulnscanner.models import Finding, Risk


def _f(owasp):
    return Finding("X", "h", Risk.ALTO, "d", owasp=owasp)


def test_controles_por_categoria_owasp():
    ctr = compliance.controles_de(_f("A02:2025"))  # misconfig
    assert "PCI-DSS" in ctr and "ISO 27001" in ctr and "NIST 800-53" in ctr
    assert all(ctr.values())  # ninguna lista vacía


def test_sin_owasp_no_mapea():
    assert compliance.controles_de(_f(None)) == {}


def test_categoria_desconocida_no_falla():
    assert compliance.controles_de(_f("Z99:2025")) == {}


def test_resumen_agrupa_por_marco_y_control():
    fs = [_f("A02:2025"), _f("A02:2025"), _f("A04:2025")]
    res = compliance.resumen(fs)
    assert "PCI-DSS" in res
    # al menos un control con conteo >= 2 (dos hallazgos A02)
    assert any(n >= 2 for controles in res.values() for n in controles.values())


def test_resumen_vacio_sin_hallazgos_mapeables():
    assert compliance.resumen([_f(None)]) == {}
