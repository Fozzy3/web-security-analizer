"""Pruebas dirigidas a frameworks/CMS comunes (Drupal, Joomla, Laravel, paneles)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import frameworks
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200):
    return HttpResponse("http://x/", "http", status, {}, body)


def test_drupal_changelog_version(monkeypatch):
    def fake(d, ruta="/", **k):
        return _resp("\nDrupal 9.5.11, 2023-08-16\n") if ruta == "/CHANGELOG.txt" else _resp(status=404)

    monkeypatch.setattr(frameworks, "fetch", fake)
    fs = frameworks.analizar("ej.com")
    assert any("drupal" in f.hallazgo.lower() and f.riesgo is Risk.BAJO for f in fs)


def test_joomla_admin_panel(monkeypatch):
    def fake(d, ruta="/", **k):
        return (
            _resp("<title>Joomla! Administration Login</title>")
            if ruta == "/administrator/"
            else _resp(status=404)
        )

    monkeypatch.setattr(frameworks, "fetch", fake)
    fs = frameworks.analizar("ej.com")
    assert any("joomla" in f.hallazgo.lower() for f in fs)


def test_laravel_ignition_debug_es_alto(monkeypatch):
    def fake(d, ruta="/", **k):
        if ruta == "/_ignition/health-check":
            return _resp('{"can_execute_commands":true}')
        return _resp(status=404)

    monkeypatch.setattr(frameworks, "fetch", fake)
    fs = frameworks.analizar("ej.com")
    assert any("ignition" in f.hallazgo.lower() and f.riesgo is Risk.ALTO for f in fs)


def test_phpmyadmin_panel(monkeypatch):
    def fake(d, ruta="/", **k):
        return _resp("<title>phpMyAdmin</title>") if "phpmyadmin" in ruta else _resp(status=404)

    monkeypatch.setattr(frameworks, "fetch", fake)
    fs = frameworks.analizar("ej.com")
    assert any("phpmyadmin" in f.hallazgo.lower() and f.riesgo is Risk.MEDIO for f in fs)


def test_sitio_generico_no_reporta(monkeypatch):
    monkeypatch.setattr(frameworks, "fetch", lambda d, ruta="/", **k: _resp("<html>hola</html>"))
    assert frameworks.analizar("ej.com") == []
