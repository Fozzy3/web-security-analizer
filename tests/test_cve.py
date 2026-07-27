"""Tests de la lógica del módulo CVE (sin red)."""

from webvulnscanner.models import Risk
from webvulnscanner.modules import cve


def test_construir_param_usa_cpe_para_producto_conocido():
    param, modo = cve._construir_param("apache", "2.4.7")
    assert modo == "cpe"
    assert "http_server" in param and "2.4.7" in param


def test_construir_param_cae_a_keyword_para_desconocido():
    param, modo = cve._construir_param("servidor-raro", "1.0")
    assert modo == "keyword"
    assert "keywordSearch" in param


def test_score_y_severidad_desde_cvss31():
    fake = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}
    assert cve._score(fake) == 9.8
    assert cve._severidad(fake) == "CRITICAL"


def test_analizar_sin_version_no_consulta():
    fs = cve.analizar(None, None)
    assert len(fs) == 1 and fs[0].riesgo == Risk.INFO


def test_analizar_ordena_por_severidad(monkeypatch):
    monkeypatch.setattr(
        cve,
        "consultar_nvd",
        lambda p, v: [
            {"id": "CVE-1", "score": 9.8, "severidad": "CRITICAL", "resumen": "x"},
            {"id": "CVE-2", "score": 5.0, "severidad": "MEDIUM", "resumen": "y"},
        ],
    )
    fs = cve.analizar("apache", "2.4.7")
    assert fs[0].riesgo == Risk.ALTO  # CRITICAL primero
    assert "CVE-1" in fs[0].hallazgo
