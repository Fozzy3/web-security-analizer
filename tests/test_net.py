"""Tests de net: normalizar_dominio (frontera de confianza) y la capa request/sesión (Fase L)."""

from __future__ import annotations

import json as _json
import urllib.error
import urllib.request

import pytest

from webvulnscanner import net
from webvulnscanner.net import normalizar_dominio


@pytest.mark.parametrize(
    ("entrada", "esperado"),
    [
        ("example.com", "example.com"),
        ("  example.com  ", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com/", "example.com"),
        ("https://example.com/ruta/larga?a=1", "example.com"),
        ("https://example.com:8443/x", "example.com"),
        ("sub.dominio.example.co.uk", "sub.dominio.example.co.uk"),
        ("mi-sitio.example.com", "mi-sitio.example.com"),
        ("192.168.1.10", "192.168.1.10"),
        ("localhost", "localhost"),
        ("https://user:pass@example.com", "example.com"),
    ],
)
def test_normaliza(entrada, esperado):
    assert normalizar_dominio(entrada) == esperado


@pytest.mark.parametrize(
    "entrada",
    [
        "",
        "   ",
        "-oX",  # inyección de argumento en nmap
        "--config=/tmp/evil.yaml",  # inyección de argumento en nuclei
        "example.com; rm -rf /",
        "exa mple.com",
        "example..com",
        "ejemplo-.com",
        "http://",
        "a" * 300 + ".com",
    ],
)
def test_rechaza(entrada):
    with pytest.raises(ValueError, match="inválido"):
        normalizar_dominio(entrada)


# ── Fase L: capa request / sesión / throttle ─────────────────


class _FakeResp:
    """Doble de la respuesta de urlopen usable como context manager."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self.headers = headers  # tiene .items()
        self._body = body

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen(capturadas: list, respuestas: dict):
    """Devuelve un urlopen falso: registra cada Request y responde por esquema.

    `respuestas[esquema]` puede ser (status, headers, body_bytes) o una Exception.
    """

    def fake(req, timeout=None, context=None):
        capturadas.append(req)
        esquema = req.full_url.split("://", 1)[0]
        r = respuestas.get(esquema)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise urllib.error.URLError("sin respuesta")
        status, headers, body = r
        return _FakeResp(status, headers, body)

    return fake


@pytest.fixture(autouse=True)
def _reset_sesion():
    """Cada test empieza sin sesión activa (evita fugas entre tests)."""
    yield
    net.configurar_sesion(net.Sesion())


def test_request_post_form(monkeypatch):
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    net.request("example.com", "/x", method="POST", data={"a": "1", "b": "2"})
    req = cap[0]
    assert req.get_method() == "POST"
    assert req.get_header("Content-type") == "application/x-www-form-urlencoded"
    assert b"a=1" in req.data and b"b=2" in req.data


def test_request_json_body(monkeypatch):
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    net.request("example.com", "/api", method="POST", json={"a": 1})
    req = cap[0]
    assert req.get_header("Content-type") == "application/json"
    assert _json.loads(req.data) == {"a": 1}


def test_request_get_por_defecto(monkeypatch):
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    r = net.request("example.com", "/")
    assert cap[0].get_method() == "GET"
    assert r is not None and r.status == 200


def test_fetch_sigue_funcionando(monkeypatch):
    """fetch() delega en request pero conserva su comportamiento GET."""
    cap: list = []
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        _fake_urlopen(cap, {"https": (200, {"Content-Type": "text/html"}, b"<html>hola</html>")}),
    )
    r = net.fetch("example.com", "/")
    assert cap[0].get_method() == "GET"
    assert r is not None
    assert r.esquema == "https" and r.status == 200
    assert r.body == "<html>hola</html>"
    assert r.header("content-type") == "text/html"


def test_fetch_fallback_https_a_http(monkeypatch):
    cap: list = []
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        _fake_urlopen(
            cap,
            {"https": urllib.error.URLError("no tls"), "http": (200, {}, b"plano")},
        ),
    )
    r = net.fetch("example.com", "/")
    assert r is not None and r.esquema == "http" and r.body == "plano"


def test_sesion_headers_se_aplican(monkeypatch):
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    net.configurar_sesion(net.Sesion(headers={"Cookie": "sid=abc", "Authorization": "Bearer T0ken"}))
    net.request("example.com", "/privado")
    req = cap[0]
    assert req.get_header("Cookie") == "sid=abc"
    assert req.get_header("Authorization") == "Bearer T0ken"


def test_sesion_no_filtra_secreto_en_log(monkeypatch, caplog):
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    net.configurar_sesion(net.Sesion(headers={"Authorization": "Bearer SUPERSECRETO"}))
    with caplog.at_level("DEBUG", logger="webvulnscanner"):
        net.request("example.com", "/privado")
    assert "SUPERSECRETO" not in caplog.text


def test_sin_sesion_omite_headers_de_auth(monkeypatch):
    """request(sin_sesion=True) no adjunta las credenciales (forced browsing)."""
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    net.configurar_sesion(net.Sesion(headers={"Cookie": "sid=abc"}))
    net.request("example.com", "/admin", sin_sesion=True)
    assert cap[0].get_header("Cookie") is None


def test_throttle_espacia_peticiones(monkeypatch):
    """Sesion.delay hace dormir entre peticiones (no antes de la primera)."""
    cap: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(cap, {"https": (200, {}, b"ok")}))
    dormidas: list[float] = []
    monkeypatch.setattr(net.time, "sleep", lambda s: dormidas.append(s))
    net.configurar_sesion(net.Sesion(delay=0.5))
    for _ in range(3):
        net.request("example.com", "/")
    # 3 peticiones → 2 esperas (la primera no espera), cada una ~0.5s
    assert len(dormidas) == 2
    assert all(d >= 0.4 for d in dormidas)
