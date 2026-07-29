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


def test_render_texto_muestra_cwe_cvss_y_compliance():
    r = ScanResult(
        "ej.com",
        ip="1.2.3.4",
        findings=[
            Finding(
                "Inyección",
                "Posible XSS reflejado en / (parámetro 'q', GET)",
                Risk.ALTO,
                "d",
                owasp="A05:2025",
                cwe="CWE-79",
                cvss={"vector": "CVSS:3.1/...", "score": 6.1},
            )
        ],
    )
    txt = report.render_texto(r, timestamp="2026-01-01 00:00:00")
    assert "CWE-79" in txt and "6.1" in txt
    assert "CUMPLIMIENTO" in txt.upper()  # sección de controles afectados


def test_render_json_valido_y_completo():
    js = json.loads(report.render_json(_result(), timestamp="2026-01-01 00:00:00"))
    assert js["meta"]["dominio"] == "ej.com"
    assert js["resumen"]["alto"] == 1
    assert js["resumen"]["ok"] == 1
    assert len(js["hallazgos"]) == 3
    assert js["hallazgos"][0]["riesgo"] == "alto"


def test_guardar_escribe_tres_archivos(tmp_path):
    txt, jsp, htm = report.guardar(_result(), tmp_path)
    assert txt.exists() and jsp.exists() and htm.exists()
    assert txt.suffix == ".txt" and jsp.suffix == ".json" and htm.suffix == ".html"
    json.loads(jsp.read_text(encoding="utf-8"))  # no lanza
    assert "<!doctype html>" in htm.read_text(encoding="utf-8").lower()


def test_html_escapa_contenido_remoto():
    from webvulnscanner import html as html_report
    from webvulnscanner.models import Finding, Risk, ScanResult

    malicioso = ScanResult(
        "x.com",
        findings=[
            Finding("M", "<script>alert(1)</script>", Risk.ALTO, "desc <img src=x onerror=y>"),
        ],
    )
    out = html_report.render(malicioso)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
