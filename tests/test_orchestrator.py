"""Tests del orquestador con los módulos de red parcheados (sin tocar Internet)."""

import webvulnscanner.orchestrator as orch
from webvulnscanner.models import Finding, Risk


def _patch_todo(monkeypatch, ip="1.2.3.4"):
    """Parchea fetch, recon y todos los módulos con dobles deterministas."""
    monkeypatch.setattr(orch, "fetch", lambda d: None)
    info = {"ip": ip, "producto": "apache", "version": "2.4.7", "servidor": "Apache/2.4.7"}
    monkeypatch.setattr(
        orch.recon, "analizar", lambda d, r: ([Finding("Reconocimiento", "ok", Risk.INFO, "x")], info)
    )
    # attr del módulo -> clave canónica en el orquestador (dns_records → "dns")
    modulos = {
        "ports": "ports",
        "tls": "tls",
        "headers": "headers",
        "dns_records": "dns",
        "subdomains": "subdomains",
        "disclosure": "disclosure",
        "waf": "waf",
        "fingerprint": "fingerprint",
        "cve": "cve",
    }
    for attr, clave in modulos.items():
        mod = getattr(orch, attr)
        monkeypatch.setattr(
            mod, "analizar", lambda *a, _k=clave: [Finding(_k, f"hallazgo {_k}", Risk.OK, "d")]
        )
    # Módulos nuevos (evitan red en tests): devuelven vacío.
    monkeypatch.setattr(orch.webchecks, "analizar", lambda *a: [])
    monkeypatch.setattr(orch.retire_js, "analizar_scripts", lambda *a: [])
    monkeypatch.setattr(orch.secrets, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.crawler, "rastrear", lambda *a, **k: orch.crawler.Crawl())
    for fn in ("subfinder", "testssl", "nuclei", "nmap", "wpscan"):
        monkeypatch.setattr(orch.external, fn, lambda *a, **k: [])


def test_run_scan_ensambla_todos_los_modulos(monkeypatch):
    _patch_todo(monkeypatch)
    result = orch.run_scan("ej.com", paralelo=False)
    assert result.ip == "1.2.3.4"
    modulos = {f.modulo for f in result.findings}
    # recon + 9 módulos
    assert "Reconocimiento" in modulos
    assert {
        "ports",
        "tls",
        "headers",
        "dns",
        "subdomains",
        "disclosure",
        "waf",
        "fingerprint",
        "cve",
    } <= modulos


def test_run_scan_respeta_activos(monkeypatch):
    _patch_todo(monkeypatch)
    result = orch.run_scan("ej.com", activos={"recon", "tls"}, paralelo=False)
    modulos = {f.modulo for f in result.findings}
    assert "tls" in modulos
    assert "ports" not in modulos and "cve" not in modulos


def test_run_scan_paralelo_da_igual_resultado(monkeypatch):
    _patch_todo(monkeypatch)
    seq = orch.run_scan("ej.com", paralelo=False)
    par = orch.run_scan("ej.com", paralelo=True)
    assert [f.modulo for f in seq.findings] == [f.modulo for f in par.findings]


def test_modulo_que_falla_no_aborta_escaneo(monkeypatch):
    _patch_todo(monkeypatch)

    def revienta():
        raise RuntimeError("boom")

    monkeypatch.setattr(orch.tls, "analizar", lambda *a: revienta())
    result = orch.run_scan("ej.com", paralelo=False)
    # El escaneo termina y registra el fallo como finding informativo
    assert any("falló" in f.hallazgo for f in result.findings)
    assert any(f.modulo == "cve" for f in result.findings)  # los demás sí corrieron


def test_dominio_que_no_resuelve_se_detiene(monkeypatch):
    monkeypatch.setattr(orch, "fetch", lambda d: None)
    monkeypatch.setattr(
        orch.recon, "analizar", lambda d, r: ([Finding("Reconocimiento", "no resuelve", Risk.ALTO, "x")], {})
    )
    result = orch.run_scan("nope.invalid", paralelo=False)
    assert result.ip is None
    assert len(result.findings) == 1  # solo el finding de recon
