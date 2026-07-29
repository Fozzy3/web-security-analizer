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


def test_scan_nunca_corre_modo_activo(client):
    """El modo activo no debe ser alcanzable por HTTP."""
    c, fake = client
    c.post("/scan", json={"dominio": "example.com", "activos": ["fuzzing", "nuclei"]})
    assert fake.kw["activos"] == set()
    assert "autorizado" not in fake.kw


def test_dominio_invalido_da_400(client):
    c, _ = client
    r = c.post("/scan", json={"dominio": "no-valido"})
    assert r.status_code == 400
    assert "inválido" in r.json()["detail"]


def test_falta_dominio_da_422(client):
    c, _ = client
    assert c.post("/scan", json={}).status_code == 422
