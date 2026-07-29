"""Pruebas dirigidas a WordPress: pivotea sobre el CMS detectado (pasivo)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import wordpress
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200, url="http://x/", headers=None):
    return HttpResponse(url, "http", status, {k.lower(): v for k, v in (headers or {}).items()}, body)


def test_enumeracion_usuarios_rest(monkeypatch):
    # Respuesta real: UNA cuenta (webmaster, id 1) + IP interna en el campo url.
    users = '[{"id":1,"name":"webmaster","slug":"webmaster","url":"http://10.20.230.177"}]'

    def fake(d, ruta="/", **k):
        return _resp(users) if "wp-json/wp/v2/users" in ruta else _resp(status=404)

    monkeypatch.setattr(wordpress, "fetch", fake)
    fs = wordpress.analizar("ej.com")
    u = [f for f in fs if "cuenta" in f.hallazgo.lower()]
    assert u and u[0].riesgo is Risk.ALTO
    assert "id 1: webmaster" in (u[0].evidencia or "")
    assert "1 cuenta de usuario" in u[0].hallazgo  # preciso: una, no "los usuarios"


def test_enumeracion_usuarios_expone_ip_interna(monkeypatch):
    users = '[{"id":1,"name":"webmaster","slug":"webmaster","url":"http://10.20.230.177"}]'
    monkeypatch.setattr(
        wordpress, "fetch", lambda d, ruta="/", **k: _resp(users) if "users" in ruta else _resp(status=404)
    )
    fs = wordpress.analizar("ej.com")
    ip = [f for f in fs if "ip interna" in f.hallazgo.lower()]
    assert ip and ip[0].riesgo is Risk.MEDIO and "10.20.230.177" in (ip[0].evidencia or "")


def test_xmlrpc_habilitado(monkeypatch):
    def fake(d, ruta="/", **k):
        if ruta == "/xmlrpc.php":
            return _resp("XML-RPC server accepts POST requests only.", status=405)
        return _resp(status=404)

    monkeypatch.setattr(wordpress, "fetch", fake)
    fs = wordpress.analizar("ej.com")
    assert any("xmlrpc" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_enumeracion_autor_por_redireccion(monkeypatch):
    def fake(d, ruta="/", **k):
        if ruta.startswith("/?author="):
            return _resp(url="https://ej.com/author/mgomez/")  # WP redirige al slug
        return _resp(status=404)

    monkeypatch.setattr(wordpress, "fetch", fake)
    fs = wordpress.analizar("ej.com")
    a = [f for f in fs if "autor" in f.hallazgo.lower()]
    assert a and "mgomez" in (a[0].evidencia or "")


def test_readme_revela_version(monkeypatch):
    def fake(d, ruta="/", **k):
        if ruta == "/readme.html":
            return _resp("<h1>WordPress</h1> Version 6.5.2")
        return _resp(status=404)

    monkeypatch.setattr(wordpress, "fetch", fake)
    fs = wordpress.analizar("ej.com")
    assert any("readme" in f.hallazgo.lower() and "6.5.2" in (f.evidencia or "") for f in fs)


def test_no_wordpress_no_reporta(monkeypatch):
    monkeypatch.setattr(wordpress, "fetch", lambda d, ruta="/", **k: _resp(status=404))
    assert wordpress.analizar("ej.com") == []
