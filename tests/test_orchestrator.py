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
    monkeypatch.setattr(orch.csrf, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.jwt_audit, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.api_discovery, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.cloud, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.mail_transport, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.sbom, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.wordpress, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.frameworks, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.stack, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.tls_deep, "analizar", lambda *a, **k: [])
    monkeypatch.setattr(orch.crawler, "rastrear", lambda *a, **k: orch.crawler.Crawl())
    monkeypatch.setattr(orch.shodan_intel, "analizar", lambda *a, **k: [])  # InternetDB: sin red en tests
    for fn in ("subfinder", "testssl", "nuclei", "nmap", "wpscan"):
        monkeypatch.setattr(orch.external, fn, lambda *a, **k: [])
    # Módulos ACTIVOS: ahora corren siempre (sin gate) → mockear para no tocar red.
    for fn in (
        "analizar_cookies",
        "analizar_cors",
        "analizar_inyeccion",
        "analizar_open_redirect",
        "analizar_fuzzing",
    ):
        monkeypatch.setattr(orch.active, fn, lambda *a, **k: [])
    for mod in ("access_control", "auth_test", "ssrf", "error_audit", "rate_limit", "api_fuzz"):
        monkeypatch.setattr(getattr(orch, mod), "analizar", lambda *a, **k: [])


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


def test_run_scan_activa_la_sesion(monkeypatch):
    """La sesión (auth + throttle) debe fijarse en net antes de correr módulos."""
    from webvulnscanner import net

    activada: dict = {}
    monkeypatch.setattr(orch, "configurar_sesion", lambda s: activada.setdefault("s", s))
    monkeypatch.setattr(orch, "fetch", lambda d: None)
    monkeypatch.setattr(orch, "_run_recon", lambda d, r: ([], {}))  # sin ip → corte temprano
    sesion = net.Sesion(headers={"Cookie": "sid=abc"}, delay=0.2)
    orch.run_scan("example.com", sesion=sesion, activos=set())
    assert activada["s"] is sesion


def test_run_scan_sin_sesion_no_falla(monkeypatch):
    monkeypatch.setattr(orch, "fetch", lambda d: None)
    monkeypatch.setattr(orch, "_run_recon", lambda d, r: ([], {}))
    # No debe lanzar aunque no se pase sesión.
    orch.run_scan("example.com", activos=set())


def test_dedupe_cves_elimina_repetidos():
    from webvulnscanner.models import Finding, Risk

    fs = [
        Finding("CVE", "CVE-2021-23017 — nginx 1.18.0", Risk.ALTO, "d"),
        Finding("CVE", "CVE-2021-23017 — Nginx 1.18.0 (por stack)", Risk.ALTO, "d"),  # duplicado
        Finding("CVE", "CVE-2023-44487 — nginx", Risk.ALTO, "d"),
        Finding("Headers", "otro hallazgo", Risk.BAJO, "d"),
    ]
    out = orch._dedupe_cves(fs)
    ids = [f.hallazgo.split(" ")[0] for f in out if f.hallazgo.startswith("CVE-")]
    assert ids == ["CVE-2021-23017", "CVE-2023-44487"]  # sin el duplicado
    assert len(out) == 3


def test_csrf_es_pasivo_inyeccion_es_activa():
    """CSRF (pasivo) disponible siempre; la inyección profunda solo con autorización."""
    pasivos = {n for n, _ in orch.MODULOS}
    activos = {n for n, _ in orch.MODULOS_ACTIVOS}
    assert "csrf" in pasivos and "csrf" not in activos
    assert "inyeccion" in activos and "inyeccion" not in pasivos


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


def test_run_scan_dos_fases_emite_parcial(monkeypatch):
    """Fase 1 emite un informe parcial con las herramientas lentas 'en progreso';
    la fase 2 (nuclei/testssl/…) las completa en el resultado final."""
    _patch_todo(monkeypatch)
    parciales = []
    result = orch.run_scan(
        "ej.com", paralelo=False, on_parcial=lambda r: parciales.append(dict(r.estado_modulos))
    )
    assert len(parciales) == 1  # se emitió exactamente un informe parcial
    en_progreso = [lbl for lbl, v in parciales[0].items() if "en progreso" in v]
    assert en_progreso  # las lentas aparecen en progreso en el parcial
    # en el resultado final NINGUNA queda "en progreso"
    assert not any("en progreso" in v for v in result.estado_modulos.values())
