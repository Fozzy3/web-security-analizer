"""Tests de la caché en disco (sin red, con carpeta temporal)."""

import webvulnscanner.cache as cache


def test_cache_guarda_y_reusa(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_DIR", tmp_path)
    llamadas = {"n": 0}

    def productor():
        llamadas["n"] += 1
        return {"valor": 42}

    a = cache.cached_json("clave-x", ttl=1000, productor=productor)
    b = cache.cached_json("clave-x", ttl=1000, productor=productor)

    assert a == b == {"valor": 42}
    assert llamadas["n"] == 1  # la segunda vez vino de caché


def test_cache_ttl_cero_no_cachea(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_DIR", tmp_path)
    llamadas = {"n": 0}

    def productor():
        llamadas["n"] += 1
        return [1, 2, 3]

    cache.cached_json("k", ttl=0, productor=productor)
    cache.cached_json("k", ttl=0, productor=productor)
    assert llamadas["n"] == 2  # ttl<=0 siempre regenera


def test_cache_expira(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_DIR", tmp_path)
    llamadas = {"n": 0}

    def productor():
        llamadas["n"] += 1
        return {"n": llamadas["n"]}

    cache.cached_json("k", ttl=1000, productor=productor)
    # Forzar expiración: mtime muy en el pasado
    for f in tmp_path.iterdir():
        import os

        os.utime(f, (0, 0))
    cache.cached_json("k", ttl=1000, productor=productor)
    assert llamadas["n"] == 2
