"""Fase N: análisis de debilidades en JWT (pasivo, decodifica no falsifica)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from webvulnscanner.models import Risk
from webvulnscanner.modules import jwt_audit


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    h, p = _b64(header), _b64(payload)
    if secret is None:
        return f"{h}.{p}."
    firma = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(firma).rstrip(b'=').decode()}"


def _niveles(findings) -> set[Risk]:
    return {f.riesgo for f in findings}


def test_alg_none_es_alto():
    tok = _jwt({"alg": "none"}, {"sub": "u", "exp": time.time() + 999})
    fs = jwt_audit.analizar_token(tok)
    assert any("none" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


def test_hs256_secreto_debil_es_alto():
    tok = _jwt({"alg": "HS256"}, {"sub": "u", "exp": time.time() + 999}, secret="secret")
    fs = jwt_audit.analizar_token(tok)
    alto = [f for f in fs if f.riesgo is Risk.ALTO]
    assert alto and "secret" in (alto[0].evidencia or "")


def test_sin_exp_es_medio():
    tok = _jwt({"alg": "HS256"}, {"sub": "u"}, secret="uNsEcReToLargoQueNoEstaEnLaLista_9137")
    assert Risk.MEDIO in _niveles(jwt_audit.analizar_token(tok))


def test_exp_vencido_es_bajo():
    tok = _jwt({"alg": "HS256"}, {"sub": "u", "exp": 1}, secret="uNsEcReToLargoQueNoEstaEnLaLista_9137")
    assert Risk.BAJO in _niveles(jwt_audit.analizar_token(tok))


def test_jwt_fuerte_no_marca():
    tok = _jwt({"alg": "RS256"}, {"sub": "u", "exp": time.time() + 9999})
    assert jwt_audit.analizar_token(tok) == []


def test_token_malformado_no_revienta():
    assert jwt_audit.analizar_token("no.es.jwt") == []
    assert jwt_audit.analizar_token("una-sola-parte") == []


def test_analizar_cosecha_tokens_del_contenido(monkeypatch):
    tok = _jwt({"alg": "none"}, {"sub": "u"})
    monkeypatch.setattr(jwt_audit, "fetch", lambda d, ruta="/", **k: _Resp(f"var t='{tok}'"))
    fs = jwt_audit.analizar("ej.com", set())
    assert any(f.riesgo is Risk.ALTO for f in fs)


class _Resp:
    def __init__(self, body):
        self.body = body
