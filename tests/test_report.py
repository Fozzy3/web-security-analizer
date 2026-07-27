import json

from webvulnscanner import report
from webvulnscanner.models import Finding, Risk, ScanResult


def _result():
    return ScanResult(
        "ej.com",
        ip="1.2.3.4",
        servidor="nginx",
        findings=[
            Finding("TLS/HTTPS", "Certificado expirado", Risk.ALTO, "grave", referencia="http://ref"),
            Finding("Headers HTTP", "HSTS presente", Risk.OK, "bien"),
            Finding("Reconocimiento", "IP resuelta", Risk.INFO, "info"),
        ],
    )


def test_render_texto_incluye_secciones_y_conteo():
    txt = report.render_texto(_result(), timestamp="2026-01-01 00:00:00")
    assert "ej.com" in txt and "1.2.3.4" in txt
    assert "PROBLEMAS CRÍTICOS" in txt
    assert "Certificado expirado" in txt
    assert "ref: http://ref" in txt
    assert "BUENAS PRÁCTICAS CONFIRMADAS" in txt


def test_render_json_valido_y_completo():
    js = json.loads(report.render_json(_result(), timestamp="2026-01-01 00:00:00"))
    assert js["meta"]["dominio"] == "ej.com"
    assert js["resumen"]["alto"] == 1
    assert js["resumen"]["ok"] == 1
    assert len(js["hallazgos"]) == 3
    assert js["hallazgos"][0]["riesgo"] == "alto"


def test_guardar_escribe_dos_archivos(tmp_path):
    txt, jsp = report.guardar(_result(), tmp_path)
    assert txt.exists() and jsp.exists()
    assert txt.suffix == ".txt" and jsp.suffix == ".json"
    json.loads(jsp.read_text(encoding="utf-8"))  # no lanza
