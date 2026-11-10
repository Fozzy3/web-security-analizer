"""Fase T: SBOM CycloneDX + dependency confusion (A03:2025, pasivo)."""

from __future__ import annotations

from webvulnscanner import sbom
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200):
    return HttpResponse("http://x/", "http", status, {}, body)


# ── SBOM CycloneDX ───────────────────────────────────────────


def test_sbom_cyclonedx_valido_con_componentes():
    doc = sbom.generar([{"name": "jquery", "version": "1.8.2"}, {"name": "nginx", "version": "1.18.0"}])
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    nombres = {c["name"] for c in doc["components"]}
    assert nombres == {"jquery", "nginx"}
    assert all(c["type"] == "library" for c in doc["components"])


def test_sbom_vacio_es_valido():
    doc = sbom.generar([])
    assert doc["specVersion"] == "1.5" and doc["components"] == []


def test_sbom_incluye_cve_conocido_del_componente():
    doc = sbom.generar([{"name": "nginx", "version": "1.18.0", "cves": ["CVE-2021-23017"]}])
    comp = doc["components"][0]
    ref = comp["bom-ref"]
    assert ref  # el componente tiene un bom-ref referenciable
    vulns = doc.get("vulnerabilities", [])
    assert any(
        v["id"] == "CVE-2021-23017" and "source" in v and any(a["ref"] == ref for a in v["affects"])
        for v in vulns
    )


def test_sbom_sin_cves_sigue_valido_sin_vulnerabilities():
    doc = sbom.generar([{"name": "jquery", "version": "1.8.2"}])
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert doc.get("vulnerabilities", []) == []


def test_componentes_de_asocia_cve_al_componente():
    fs = [
        Finding("Fingerprint", "Tecnología: nginx 1.18.0", Risk.INFO, "d"),
        Finding(
            "CVE",
            "CVE-2021-23017 — nginx 1.18.0 (CVSS 9.8 CRITICAL)",
            Risk.ALTO,
            "desbordamiento en el resolver",
            referencia="https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
            evidencia="match: nginx 1.18.0",
        ),
    ]
    comps = sbom.componentes_de(fs)
    nginx = [c for c in comps if c["name"].lower() == "nginx"]
    assert len(nginx) == 1  # deduplicado pese a venir de dos módulos
    assert "CVE-2021-23017" in nginx[0]["cves"]


def test_componentes_de_findings_extrae_nombre_version():
    fs = [
        Finding("Fingerprint", "Tecnología: nginx 1.18.0", Risk.INFO, "d"),
        Finding("JS vulnerable", "jQuery 1.8.2 (vulnerable)", Risk.MEDIO, "d"),
        Finding("Reconocimiento", "IP resuelta 1.2.3.4", Risk.INFO, "d"),  # sin versión → se ignora
    ]
    comps = sbom.componentes_de(fs)
    nombres = {c["name"].lower() for c in comps}
    assert "nginx" in nombres and "jquery" in nombres
    assert not any("ip" in n for n in nombres)


# ── dependency confusion ─────────────────────────────────────


def test_detecta_paquete_interno_scoped():
    assert sbom._paquetes_internos('import "@corp/internal-utils"') == {"@corp/internal-utils"}
    assert sbom._paquetes_internos("nada scoped aquí") == set()


def test_analizar_reporta_dependency_confusion(monkeypatch):
    monkeypatch.setattr(sbom, "fetch", lambda d, ruta="/", **k: _resp('require("@corp/secret-lib")'))
    fs = sbom.analizar("ej.com", set())
    assert any("dependency confusion" in f.hallazgo.lower() and f.riesgo is Risk.BAJO for f in fs)


def test_analizar_limpio_no_reporta(monkeypatch):
    monkeypatch.setattr(sbom, "fetch", lambda d, ruta="/", **k: _resp("<html>hola</html>"))
    assert sbom.analizar("ej.com", set()) == []
