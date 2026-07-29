"""Tests del punto de entrada CLI: resolución de módulos, salida y códigos de retorno.

El escaneo real se sustituye por un `run_scan` falso: aquí interesa el pegamento
(argumentos → módulos → archivos → exit code), no la red.
"""

from __future__ import annotations

import json

import pytest

import webvulnscanner.orchestrator as orch
from webvulnscanner import cli
from webvulnscanner.models import Finding, Risk, ScanResult


def _resultado(*riesgos: Risk) -> ScanResult:
    return ScanResult(
        dominio="example.com",
        ip="93.184.216.34",
        servidor="nginx",
        findings=[Finding("test", f"hallazgo {i}", r, "descripción") for i, r in enumerate(riesgos)],
    )


@pytest.fixture
def fake_scan(monkeypatch):
    """Sustituye run_scan y registra con qué se llamó."""
    llamadas: list[dict] = []
    salida = {"result": _resultado(Risk.BAJO)}

    def _fake(dominio, **kw):
        llamadas.append({"dominio": dominio, **kw})
        return salida["result"]

    monkeypatch.setattr(cli, "run_scan", _fake)
    return llamadas, salida


# ── resolución de módulos ────────────────────────────────────


def test_sin_perfil_incluye_todo():
    """Sin gate: por defecto corre TODO (pasivos + activos)."""
    activos = cli._resolver_activos(None, None, None)
    assert "recon" in activos
    assert "fuzzing" in activos  # activo: ahora siempre incluido


def test_perfil_full_incluye_activos():
    activos = cli._resolver_activos("full", None, None)
    assert {"fuzzing", "cookies", "nuclei"} <= activos
    assert activos == cli._resolver_activos(None, None, None)


def test_perfil_quick_es_subconjunto():
    activos = cli._resolver_activos("quick", None, None)
    assert activos == {"recon", "tls", "headers", "waf", "fingerprint"}


def test_only_gana_sobre_perfil():
    assert cli._resolver_activos("quick", "tls,dns", None) == {"tls", "dns"}


def test_skip_resta():
    activos = cli._resolver_activos("quick", None, "tls,waf")
    assert activos == {"recon", "headers", "fingerprint"}


def test_modulo_desconocido_falla():
    with pytest.raises(SystemExit):
        cli._resolver_activos(None, "noexiste", None)


def test_only_modulo_activo_permitido():
    """Sin gate: pedir un módulo activo por --only ya es válido."""
    assert cli._resolver_activos(None, "fuzzing", None) == {"fuzzing"}


# ── main() ───────────────────────────────────────────────────


def test_dominio_vacio_retorna_1(capsys):
    """Sin dominio y sin TTY (pipe/CI) no debe colgarse pidiendo input()."""
    assert cli.main([]) == 1
    assert "debe indicar un dominio" in capsys.readouterr().err


def test_dominio_invalido_retorna_1(capsys, fake_scan, monkeypatch):
    monkeypatch.setattr(
        cli, "run_scan", lambda *a, **kw: (_ for _ in ()).throw(ValueError("Dominio inválido"))
    )
    assert cli.main(["-- -evil", "--no-save"]) == 1
    assert "Dominio inválido" in capsys.readouterr().err


def test_exit_code_0_sin_riesgo_alto(fake_scan):
    assert cli.main(["example.com", "--no-save", "-q"]) == 0


def test_exit_code_2_con_riesgo_alto(fake_scan):
    _, salida = fake_scan
    salida["result"] = _resultado(Risk.ALTO)
    assert cli.main(["example.com", "--no-save", "-q"]) == 2


def test_no_save_no_escribe(tmp_path, fake_scan):
    cli.main(["example.com", "--no-save", "-o", str(tmp_path), "-q"])
    assert list(tmp_path.iterdir()) == []


def test_guarda_txt_json_html(tmp_path, fake_scan):
    cli.main(["example.com", "-o", str(tmp_path), "-q"])
    sufijos = {p.suffix for p in tmp_path.iterdir()}
    assert sufijos == {".txt", ".json", ".html"}


def test_sarif_escribe_archivo_valido(tmp_path, fake_scan):
    cli.main(["example.com", "-o", str(tmp_path), "--sarif", "-q"])
    (sarif_file,) = [p for p in tmp_path.iterdir() if p.suffix == ".sarif"]
    doc = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_scan_incluye_activos_por_defecto(fake_scan):
    """Sin gate: cada escaneo del CLI incluye los módulos activos."""
    llamadas, _ = fake_scan
    cli.main(["example.com", "--no-save", "-q"])
    assert "fuzzing" in llamadas[0]["activos"]
    assert "autorizado" not in llamadas[0]  # el parámetro ya no existe


def test_no_parallel_propaga_al_scan(fake_scan):
    llamadas, _ = fake_scan
    cli.main(["example.com", "--no-parallel", "--no-save", "-q"])
    assert llamadas[0]["paralelo"] is False


def test_diff_contra_reporte_previo(tmp_path, capsys, fake_scan):
    previo = tmp_path / "previo.json"
    previo.write_text(
        json.dumps({"meta": {"dominio": "example.com"}, "hallazgos": []}),
        encoding="utf-8",
    )
    assert cli.main(["example.com", "--diff", str(previo), "--no-save", "-q"]) == 0
    assert "hallazgo 0" in capsys.readouterr().out


def test_version_sale_con_0(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "WebVulnScanner" in capsys.readouterr().out


# ── Fase L: construcción de la sesión desde flags ────────────


def _sesion(argv):
    return cli._construir_sesion(cli._parse_args(argv + ["ejemplo.com"]))


def test_sesion_vacia_por_defecto():
    s = _sesion([])
    assert s.headers == {} and s.delay == 0.0


def test_cookie_va_a_header_cookie():
    assert _sesion(["--cookie", "sid=abc"]).headers == {"Cookie": "sid=abc"}


def test_bearer_va_a_authorization():
    assert _sesion(["--bearer", "T0ken"]).headers == {"Authorization": "Bearer T0ken"}


def test_header_repetible_se_parsea():
    s = _sesion(["--header", "X-Api: v1", "--header", "X-Trace: 9"])
    assert s.headers == {"X-Api": "v1", "X-Trace": "9"}


def test_delay_directo():
    assert _sesion(["--delay", "0.5"]).delay == 0.5


def test_rps_se_convierte_a_delay():
    assert _sesion(["--rps", "2"]).delay == 0.5


def test_delay_gana_sobre_rps():
    assert _sesion(["--delay", "1", "--rps", "10"]).delay == 1.0


def test_main_propaga_sesion_al_scan(fake_scan):
    llamadas, _ = fake_scan
    cli.main(["example.com", "--cookie", "sid=abc", "--no-save", "-q"])
    assert llamadas[0]["sesion"].headers == {"Cookie": "sid=abc"}


# ── Consumo de recursos: --rl-burst (API4:2023) ──────────────


def test_rl_burst_se_parsea():
    assert cli._parse_args(["example.com", "--rl-burst", "5"]).rl_burst == 5


def test_rl_burst_default_razonable():
    """Sin flag, cae en el default del módulo rate_limit (12)."""
    assert cli._parse_args(["example.com"]).rl_burst == 12


def _patch_rate_limit(monkeypatch) -> dict:
    """Corta la red y captura con qué `burst` se invoca rate_limit.analizar."""
    capturado: dict = {}
    monkeypatch.setattr(orch, "fetch", lambda d: None)
    info = {"ip": "1.2.3.4"}
    monkeypatch.setattr(
        orch.recon,
        "analizar",
        lambda d, r: ([Finding("Reconocimiento", "ok", Risk.INFO, "x")], info),
    )

    def _fake_rl(dominio, *, burst=12):
        capturado["burst"] = burst
        return []

    monkeypatch.setattr(orch.rate_limit, "analizar", _fake_rl)
    return capturado


def test_rl_burst_llega_a_rate_limit(monkeypatch):
    capturado = _patch_rate_limit(monkeypatch)
    cli.main(["example.com", "--only", "rate_limit", "--rl-burst", "5", "--no-save", "-q"])
    assert capturado["burst"] == 5


def test_rl_burst_default_llega_a_rate_limit(monkeypatch):
    capturado = _patch_rate_limit(monkeypatch)
    cli.main(["example.com", "--only", "rate_limit", "--no-save", "-q"])
    assert capturado["burst"] == 12


# ── Caracterización: --sbom escribe un CycloneDX válido ───────


def test_sbom_escribe_cyclonedx_valido(tmp_path, fake_scan):
    _, salida = fake_scan
    salida["result"] = ScanResult(
        dominio="example.com",
        findings=[Finding("Fingerprint", "Servidor nginx 1.18.0", Risk.INFO, "Server: nginx/1.18.0")],
    )
    destino = tmp_path / "sbom.json"
    cli.main(["example.com", "--sbom", str(destino), "--no-save", "-q"])
    doc = json.loads(destino.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert any(c["name"].lower() == "nginx" and c["version"] == "1.18.0" for c in doc["components"])
