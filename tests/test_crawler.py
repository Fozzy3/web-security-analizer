import webvulnscanner.crawler as crawler
from webvulnscanner.net import HttpResponse

_HTML = """
<html><body>
  <a href="/productos?cat=1">productos</a>
  <a href="/nosotros">nosotros</a>
  <a href="https://externo.com/x">externo</a>
  <script src="/static/jquery-1.8.2.min.js"></script>
  <form action="/buscar" method="post">
    <input name="q"><input name="token" type="hidden">
  </form>
</body></html>
"""


def test_parser_extrae_enlaces_scripts_forms():
    p = crawler._Parser("http://ej.com/")
    p.feed(_HTML)
    assert "http://ej.com/productos?cat=1" in p.enlaces
    assert any("jquery-1.8.2" in s for s in p.scripts)
    assert p.forms and p.forms[0].action == "http://ej.com/buscar"
    assert p.forms[0].method == "post"
    assert p.forms[0].inputs == ["q", "token"]


def test_mismo_host():
    assert crawler._mismo_host("http://ej.com/x", "ej.com")
    assert crawler._mismo_host("http://www.ej.com/x", "ej.com")
    assert not crawler._mismo_host("http://otro.com/x", "ej.com")


def test_rastrear_descubre_params_y_scripts(monkeypatch):
    def fake_fetch(dominio, ruta="/", **k):
        return HttpResponse(f"http://{dominio}{ruta}", "http", 200, {"content-type": "text/html"}, _HTML)

    monkeypatch.setattr(crawler, "fetch", fake_fetch)
    c = crawler.rastrear("ej.com", max_paginas=3, max_prof=1)
    assert "cat" in c.params.get("/productos", set())
    assert any("jquery" in s for s in c.scripts)
    assert len(c.forms) >= 1
