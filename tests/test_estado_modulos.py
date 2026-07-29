"""Estado de ejecución por módulo, motores externos, Shodan gratis y comando doctor."""

from __future__ import annotations

import json

from webvulnscanner import cli, informe, orchestrator, report, tools
from webvulnscanner.models import Finding, Risk, ScanResult
from webvulnscanner.modules import shodan_intel


def test_estado_modulos_clasifica_analizado_omitido_fallo(monkeypatch):
    monkeypatch.setattr(tools, "disponible", lambda _b: False)  # ningún binario externo
    orden = [
        ("recon", "Reconocimiento"),
        ("headers", "Headers HTTP"),
        ("nmap", "nmap (externo)"),
        ("shodan", "Inteligencia Shodan"),  # ya no depende de key → analizado
        ("jwt", "JWT"),
        ("cors", "CORS"),  # no seleccionado
    ]
    resultados = {
        "headers": [Finding("Headers", "CSP ausente", Risk.ALTO, "x")],
        "nmap": [],
        "shodan": [],
        "jwt": [Finding("JWT", "El módulo 'jwt' falló durante la ejecución", Risk.INFO, "boom")],
    }
    est = orchestrator._estado_modulos(orden, resultados)
    assert est["Reconocimiento"] == "analizado"
    assert est["Headers HTTP"] == "analizado"
    assert est["Inteligencia Shodan"] == "analizado"  # Shodan gratis: nunca omitido por falta de key
    assert est["nmap (externo)"].startswith("omitido")
    assert "instalar:" in est["nmap (externo)"]  # pide la instalación
    assert est["JWT"] == "falló"
    assert "CORS" not in est


def test_motor_disponible_true_cuando_instalado(monkeypatch):
    monkeypatch.setattr(tools, "disponible", lambda _b: True)
    assert tools.motor_disponible("nuclei") is True
    assert tools.motor_disponible("no-es-un-motor") is True  # claves desconocidas no bloquean


def test_motores_faltantes_incluye_comando(monkeypatch):
    monkeypatch.setattr(tools, "disponible", lambda _b: False)
    falt = dict(tools.motores_faltantes())
    assert "nmap" in falt and "dnf install" in falt["nmap"]
    assert "wpscan" in falt and "gem install" in falt["wpscan"]


# ── Shodan gratis (InternetDB) ───────────────────────────────────


def test_shodan_internetdb_gratis_sin_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.setattr(shodan_intel, "cached_json", lambda _k, _ttl, fn: fn())
    monkeypatch.setattr(
        shodan_intel,
        "_internetdb",
        lambda ip, timeout: {"ports": [80, 443], "vulns": ["CVE-2021-9999"], "hostnames": ["h.example"]},
    )
    fs = shodan_intel.analizar("1.2.3.4")
    assert any("puertos indexados" in f.hallazgo for f in fs)
    assert any("CVE" in f.hallazgo and f.riesgo is Risk.ALTO for f in fs)


def test_shodan_internetdb_ip_no_indexada_vacio(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.setattr(shodan_intel, "cached_json", lambda _k, _ttl, fn: fn())
    monkeypatch.setattr(shodan_intel, "_internetdb", lambda ip, timeout: {"_vacio": True})
    assert shodan_intel.analizar("1.2.3.4") == []


def test_shodan_sin_ip():
    assert shodan_intel.analizar(None) == []


# ── round-trip + reporte ─────────────────────────────────────────


def test_estado_modulos_roundtrip_json():
    r = ScanResult(
        "x.com",
        estado_modulos={"Headers HTTP": "analizado", "nmap": "omitido — nmap no instalado (instalar: …)"},
    )
    d = json.loads(report.render_json(r))
    assert d["estado_modulos"]["nmap"].startswith("omitido")
    assert ScanResult.from_json(d).estado_modulos == r.estado_modulos


def test_informe_muestra_cobertura():
    r = ScanResult(
        "x.com",
        estado_modulos={"Headers HTTP": "analizado", "nmap (externo)": "omitido — nmap no instalado (instalar: x)"},
    )
    html = informe.generar(r)
    assert "Cobertura del análisis" in html
    assert "Analizaron" in html and "No analizaron" in html
    assert "nmap" in html and "omitido" in html


def test_informe_sin_estado_no_rompe():
    assert "Cobertura del análisis" not in informe.generar(ScanResult("x.com"))


# ── comando doctor (--check-tools) para agentes ──────────────────


def test_cli_check_tools_lista_y_sale(capsys):
    rc = cli.main(["--check-tools"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "nmap" in out and "wpscan" in out
    assert "InternetDB" in out  # menciona la consulta gratis de Shodan


# ── informe en dos fases: sección "análisis profundo" + auto-refresh ──


def test_informe_analisis_profundo_en_progreso_con_autorefresh():
    r = ScanResult(
        "x.com",
        estado_modulos={
            "nuclei (plantillas, externo)": "en progreso — análisis profundo en curso",
            "Headers HTTP": "analizado",
        },
    )
    html = informe.generar(r)
    assert "Análisis profundo" in html
    assert "en progreso" in html
    assert 'http-equiv="refresh"' in html  # se auto-actualiza mientras hay pendientes


def test_informe_sin_pendientes_no_autorefresh():
    r = ScanResult(
        "x.com",
        estado_modulos={"nuclei (plantillas, externo)": "analizado"},
    )
    html = informe.generar(r)
    assert 'http-equiv="refresh"' not in html
    assert "Análisis profundo" in html  # la sección existe (nuclei es herramienta externa)
