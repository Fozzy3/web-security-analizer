"""Fase M: detección pasiva de CSRF (formularios POST sin token anti-CSRF)."""

from __future__ import annotations

from webvulnscanner.crawler import Crawl, Form
from webvulnscanner.models import Risk
from webvulnscanner.modules import csrf
from webvulnscanner.net import HttpResponse


def _resp(set_cookie=None):
    headers = {"set-cookie": set_cookie} if set_cookie else {}
    return HttpResponse("http://x/", "http", 200, headers, "")


def _crawl(*forms):
    c = Crawl()
    c.forms = list(forms)
    return c


def test_form_post_sin_token_es_medio():
    c = _crawl(Form(action="/transfer", method="post", inputs=["monto", "destino"]))
    fs = csrf.analizar(_resp(), c)
    assert fs and fs[0].riesgo is Risk.MEDIO
    assert "/transfer" in fs[0].hallazgo


def test_form_con_token_no_se_marca():
    c = _crawl(Form(action="/transfer", method="post", inputs=["monto", "_token"]))
    assert csrf.analizar(_resp(), c) == []


def test_samesite_baja_a_bajo():
    c = _crawl(Form(action="/transfer", method="post", inputs=["monto"]))
    fs = csrf.analizar(_resp(set_cookie="sid=abc; SameSite=Lax"), c)
    assert fs and fs[0].riesgo is Risk.BAJO


def test_form_get_se_ignora():
    c = _crawl(Form(action="/buscar", method="get", inputs=["q"]))
    assert csrf.analizar(_resp(), c) == []


def test_sin_crawl_no_falla():
    assert csrf.analizar(_resp(), None) == []
