"""Tests del fuzzing de API (schemathesis). Se prueba el parseo JUnit puro."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import api_fuzz

_JUNIT_CON_FALLO = """<?xml version="1.0"?>
<testsuites>
  <testsuite name="schemathesis" tests="2" failures="1">
    <testcase name="GET /users/{id}">
      <failure message="Server error: received 500 Internal Server Error">traceback...</failure>
    </testcase>
    <testcase name="GET /health"/>
  </testsuite>
</testsuites>"""

_JUNIT_SIN_FALLOS = """<?xml version="1.0"?>
<testsuites><testsuite name="schemathesis" tests="1" failures="0">
  <testcase name="GET /ok"/>
</testsuite></testsuites>"""


def test_parse_junit_detecta_fallo_de_servidor():
    fs = api_fuzz._parse_junit(_JUNIT_CON_FALLO)
    assert len(fs) == 1
    assert fs[0].riesgo is Risk.ALTO  # 500 → error de servidor
    assert "/users/{id}" in fs[0].hallazgo
    assert "500" in (fs[0].evidencia or "")


def test_parse_junit_sin_fallos_no_reporta():
    assert api_fuzz._parse_junit(_JUNIT_SIN_FALLOS) == []


def test_parse_junit_xml_corrupto_no_revienta():
    assert api_fuzz._parse_junit("esto no es xml <<<") == []


def test_nivel_por_tipo_de_fallo():
    assert api_fuzz._nivel("Server error: 500")[0] is Risk.ALTO
    assert api_fuzz._nivel("response_schema_conformance failed")[0] is Risk.MEDIO


def test_analizar_sin_schemathesis_devuelve_vacio(monkeypatch):
    monkeypatch.setattr(api_fuzz, "disponible", lambda: False)
    assert api_fuzz.analizar("ej.com") == []


def test_analizar_sin_openapi_devuelve_vacio(monkeypatch):
    monkeypatch.setattr(api_fuzz, "disponible", lambda: True)
    monkeypatch.setattr(api_fuzz, "_schema_url", lambda d: None)
    assert api_fuzz.analizar("ej.com") == []
