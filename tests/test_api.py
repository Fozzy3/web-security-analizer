"""Tests de la API REST. Se salta si FastAPI no está instalado (extra opcional)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")  # TestClient lo necesita
from fastapi.testclient import TestClient  # noqa: E402

from webvulnscanner import api  # noqa: E402
from webvulnscanner.models import Finding, Risk, ScanResult  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    def _fake(dominio, **kw):
        if dominio == "no-valido":
            raise ValueError("Dominio inválido: 'no-valido'")
        _fake.kw = kw
        return ScanResult(
            dominio=dominio,
            ip="1.2.3.4",
            findings=[Finding("headers", "Falta CSP", Risk.MEDIO, "descripción")],
        )

    monkeypatch.setattr(api, "run_scan", _fake)
    return TestClient(api.app), _fake


def test_health(client):
    c, _ = client
    body = c.get("/health").json()
    assert body["status"] == "ok"
    assert "recon" in body["modulos"]


def test_scan_devuelve_nota_y_reporte(client):
    c, _ = client
    body = c.post("/scan", json={"dominio": "example.com"}).json()
    assert body["nota"] == "A"
    assert body["puntaje"] == 90
    assert body["reporte"]["meta"]["dominio"] == "example.com"
    assert body["reporte"]["hallazgos"][0]["hallazgo"] == "Falta CSP"


def test_scan_filtra_modulos_desconocidos(client):
    c, fake = client
    c.post("/scan", json={"dominio": "example.com", "activos": ["tls", "inventado"]})
    assert fake.kw["activos"] == {"tls"}


def test_scan_incluye_modo_activo(client):
    """La API ahora corre TODOS los módulos (activos incluidos)."""
    c, fake = client
    c.post("/scan", json={"dominio": "example.com", "activos": ["fuzzing", "nuclei"]})
    assert fake.kw["activos"] == {"fuzzing", "nuclei"}
    assert "autorizado" not in fake.kw


def test_dominio_invalido_da_400(client):
    c, _ = client
    r = c.post("/scan", json={"dominio": "no-valido"})
    assert r.status_code == 400
    assert "inválido" in r.json()["detail"]


def test_falta_dominio_da_422(client):
    c, _ = client
    assert c.post("/scan", json={}).status_code == 422


# ── Capa web async ("pegá la URL y arranca") ─────────────────


@pytest.fixture
def web(client, monkeypatch):
    """Cliente con el job corriendo inline (sin thread) para tests deterministas."""
    c, fake = client
    monkeypatch.setattr(api, "_spawn", lambda fn: fn())  # ejecuta el job en el acto
    api._jobs.clear()
    return c, fake


def test_index_tiene_formulario_de_url(web):
    c, _ = web
    r = c.get("/")
    assert r.status_code == 200
    assert "<form" in r.text and "/ui/scan" in r.text


def test_ui_scan_crea_job_y_el_informe_muestra_hallazgos(web):
    c, _ = web
    r = c.post("/ui/scan", json={"dominio": "example.com"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert r.json()["url"].endswith(job_id)

    informe = c.get(f"/ui/report/{job_id}")
    assert informe.status_code == 200
    assert "Falta CSP" in informe.text  # el hallazgo del fake run_scan


def test_ui_report_desconocido_da_404(web):
    c, _ = web
    assert c.get("/ui/report/inexistente").status_code == 404


def test_ui_report_en_curso_muestra_espera_y_autorefresh(web):
    c, _ = web
    api._jobs["encurso"] = None  # job recién creado, sin resultado aún
    r = c.get("/ui/report/encurso")
    assert r.status_code == 200
    assert "http-equiv" in r.text.lower()  # meta refresh para actualizarse solo
