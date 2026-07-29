"""Fase R: autenticación — enumeración, default creds, rate-limit (activo, gateado)."""

from __future__ import annotations

from webvulnscanner.crawler import Crawl, Form
from webvulnscanner.models import Risk
from webvulnscanner.modules import auth_test
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200, headers=None):
    return HttpResponse("http://x/", "http", status, {k.lower(): v for k, v in (headers or {}).items()}, body)


def _crawl_login():
    c = Crawl()
    c.forms = [Form(action="/login", method="post", inputs=["username", "password"])]
    return c


# ── detección de formulario de login ─────────────────────────


def test_detecta_form_login():
    form, cu, cp = auth_test._form_login(_crawl_login())
    assert form.action == "/login" and cu == "username" and cp == "password"


def test_sin_form_login_devuelve_none():
    c = Crawl()
    c.forms = [Form(action="/buscar", method="get", inputs=["q"])]
    assert auth_test._form_login(c) is None


# ── enumeración de usuarios ──────────────────────────────────


def test_enumeracion_por_respuesta_diferencial(monkeypatch):
    def fake(d, ruta="/", *, data=None, **k):
        usuario = (data or {}).get("username", "")
        if usuario == "admin":
            return _resp("contraseña incorrecta", status=200)  # existe
        return _resp("usuario no encontrado", status=404)  # no existe

    monkeypatch.setattr(auth_test, "request", fake)
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert any("enumeraci" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_sin_diferencia_no_enumera(monkeypatch):
    monkeypatch.setattr(
        auth_test, "request", lambda d, ruta="/", **k: _resp("credenciales inválidas", status=200)
    )
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert not any("enumeraci" in f.hallazgo.lower() for f in fs)


# ── credenciales por defecto ─────────────────────────────────


def test_default_creds_validas_es_alto(monkeypatch):
    def fake(d, ruta="/", *, data=None, **k):
        u, p = (data or {}).get("username"), (data or {}).get("password")
        if (u, p) == ("admin", "admin"):
            return _resp("", status=302, headers={"Location": "/dashboard"})  # login exitoso
        return _resp("credenciales inválidas", status=200)

    monkeypatch.setattr(auth_test, "request", fake)
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert any("defecto" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


# ── rate limiting ────────────────────────────────────────────


def test_sin_rate_limit_es_medio(monkeypatch):
    monkeypatch.setattr(
        auth_test, "request", lambda d, ruta="/", **k: _resp("credenciales inválidas", status=200)
    )
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert any("rate" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_con_rate_limit_no_reporta(monkeypatch):
    def fake(d, ruta="/", *, data=None, **k):
        return _resp("demasiados intentos", status=429)

    monkeypatch.setattr(auth_test, "request", fake)
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert not any("rate" in f.hallazgo.lower() for f in fs)


def test_sin_crawl_no_falla():
    assert auth_test.analizar("ej.com", None) == []


# ── session fixation ─────────────────────────────────────────


def test_session_fixation_id_no_rota_es_medio(monkeypatch):
    fija = {"Set-Cookie": "sessionid=FIJA123; Path=/; HttpOnly"}

    def fake(d, ruta="/", *, data=None, method="GET", **k):
        u, p = (data or {}).get("username"), (data or {}).get("password")
        if method == "POST" and (u, p) == ("admin", "admin"):  # login exitoso
            return _resp("", status=302, headers={**fija, "Location": "/panel"})
        if method == "GET":  # sesión anónima pre-login
            return _resp("login", status=200, headers=fija)
        return _resp("credenciales inválidas", status=200)  # el resto de defaults falla

    monkeypatch.setattr(auth_test, "request", fake)
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert any("session fixation" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_session_fixation_id_rota_no_reporta(monkeypatch):
    def fake(d, ruta="/", *, data=None, method="GET", **k):
        u, p = (data or {}).get("username"), (data or {}).get("password")
        if method == "POST" and (u, p) == ("admin", "admin"):  # login exitoso: cookie NUEVA
            return _resp("", status=302, headers={"Set-Cookie": "sessionid=NUEVA999", "Location": "/panel"})
        if method == "GET":
            return _resp("login", status=200, headers={"Set-Cookie": "sessionid=ANON111"})
        return _resp("credenciales inválidas", status=200)

    monkeypatch.setattr(auth_test, "request", fake)
    fs = auth_test.analizar("ej.com", _crawl_login())
    assert not any("session fixation" in f.hallazgo.lower() for f in fs)
