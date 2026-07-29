"""Fase N: misconfiguración cloud (buckets públicos + referencias a metadata)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import cloud
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200):
    return HttpResponse("http://x/", "http", status, {}, body)


# ── helpers puros ────────────────────────────────────────────


def test_extrae_buckets_de_varios_proveedores():
    texto = (
        'img src="https://mibucket.s3.amazonaws.com/logo.png" '
        'href="https://storage.googleapis.com/otro/x.js" '
        "https://cuenta.blob.core.windows.net/data"
    )
    buckets = cloud._buckets(texto)
    assert any("s3" in b for b in buckets)
    assert any("googleapis" in b for b in buckets)
    assert any("blob.core.windows.net" in b for b in buckets)


def test_detecta_referencia_metadata():
    assert cloud._refs_metadata("fetch('http://169.254.169.254/latest/meta-data/')")
    assert cloud._refs_metadata("metadata.google.internal")
    assert not cloud._refs_metadata("contenido normal sin metadata cloud")


# ── comportamiento ───────────────────────────────────────────


def test_bucket_s3_publico_listable_es_alto(monkeypatch):
    home = 'src="https://mibucket.s3.amazonaws.com/logo.png"'

    def fake(d, ruta="/", **k):
        if ruta == "/":
            return _resp(home)
        return _resp(status=404)

    def fake_url(url, **k):
        return _resp("<ListBucketResult><Name>mibucket</Name></ListBucketResult>")

    monkeypatch.setattr(cloud, "fetch", fake)
    monkeypatch.setattr(cloud, "fetch_url", fake_url)
    fs = cloud.analizar("ej.com", set())
    assert any(f.riesgo is Risk.ALTO and "bucket" in f.hallazgo.lower() for f in fs)


def test_bucket_s3_privado_no_listable_no_se_reporta(monkeypatch):
    home = 'src="https://mibucket.s3.amazonaws.com/logo.png"'

    def fake(d, ruta="/", **k):
        if ruta == "/":
            return _resp(home)
        return _resp(status=404)

    def fake_url(url, **k):
        return _resp(
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
            status=403,
        )

    monkeypatch.setattr(cloud, "fetch", fake)
    monkeypatch.setattr(cloud, "fetch_url", fake_url)
    fs = cloud.analizar("ej.com", set())
    assert not any("bucket" in f.hallazgo.lower() for f in fs)


def test_referencia_metadata_es_medio(monkeypatch):
    monkeypatch.setattr(cloud, "fetch", lambda d, ruta="/", **k: _resp("app.get('http://169.254.169.254/')"))
    monkeypatch.setattr(cloud, "fetch_url", lambda url, **k: _resp(status=404))
    fs = cloud.analizar("ej.com", set())
    assert any(f.riesgo is Risk.MEDIO and "ssrf" in f.descripcion.lower() for f in fs)


def test_contenido_limpio_no_reporta(monkeypatch):
    monkeypatch.setattr(cloud, "fetch", lambda d, ruta="/", **k: _resp("<html>hola</html>"))
    monkeypatch.setattr(cloud, "fetch_url", lambda url, **k: _resp(status=404))
    assert cloud.analizar("ej.com", set()) == []
