import json

from webvulnscanner import diff, report, sarif
from webvulnscanner.models import Finding, Risk, ScanResult


def _res(findings):
    return ScanResult("ej.com", ip="1.2.3.4", servidor="nginx", findings=findings)


# ── SARIF ─────────────────────────────────────────────────────
def test_sarif_estructura_valida():
    r = _res(
        [
            Finding("TLS/HTTPS", "cert expirado", Risk.ALTO, "d"),
            Finding("Headers HTTP", "hsts ausente", Risk.MEDIO, "d"),
            Finding("DNS", "spf ok", Risk.OK, "d"),  # OK se omite
        ]
    )
    doc = json.loads(sarif.render(r))
    assert doc["version"] == "2.1.0"
    resultados = doc["runs"][0]["results"]
    assert len(resultados) == 2  # el OK no cuenta
    niveles = {x["level"] for x in resultados}
    assert niveles == {"error", "warning"}


# ── models roundtrip ──────────────────────────────────────────
def test_json_roundtrip():
    original = _res([Finding("M", "h", Risk.ALTO, "d", referencia="http://r", evidencia="e")])
    payload = json.loads(report.render_json(original))
    reconstruido = ScanResult.from_json(payload)
    assert reconstruido.dominio == "ej.com"
    assert reconstruido.findings[0].riesgo == Risk.ALTO
    assert reconstruido.findings[0].referencia == "http://r"


# ── diff ──────────────────────────────────────────────────────
def test_diff_detecta_nuevos_y_resueltos():
    antes = _res(
        [
            Finding("TLS", "problema-A", Risk.ALTO, "d"),
            Finding("DNS", "comun", Risk.INFO, "d"),
        ]
    )
    ahora = _res(
        [
            Finding("DNS", "comun", Risk.INFO, "d"),
            Finding("Headers", "problema-B", Risk.MEDIO, "d"),
        ]
    )
    d = diff.comparar(antes, ahora)
    assert [f.hallazgo for f in d.nuevos] == ["problema-B"]
    assert [f.hallazgo for f in d.resueltos] == ["problema-A"]
    assert d.sin_cambios == 1


def test_diff_cargar_reporte(tmp_path):
    r = _res([Finding("M", "h", Risk.ALTO, "d")])
    _, js, _ = report.guardar(r, tmp_path)
    cargado = diff.cargar_reporte(js)
    assert cargado.findings[0].hallazgo == "h"
