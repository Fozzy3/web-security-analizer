"""Fase N: seguridad de transporte de correo (MTA-STS + TLS-RPT)."""

from __future__ import annotations

from webvulnscanner.models import Risk
from webvulnscanner.modules import mail_transport
from webvulnscanner.net import HttpResponse


def _resp(body="", status=200):
    return HttpResponse("http://x/", "http", status, {}, body)


def _nivel(findings, fragmento) -> Risk:
    return next(f.riesgo for f in findings if fragmento.lower() in f.hallazgo.lower())


def test_modo_mta_sts_parsea():
    assert mail_transport._modo_mta_sts("version: STSv1\nmode: enforce\nmax_age: 604800") == "enforce"
    assert mail_transport._modo_mta_sts("mode: testing") == "testing"
    assert mail_transport._modo_mta_sts("sin modo") is None


def test_mta_sts_enforce_es_ok(monkeypatch):
    monkeypatch.setattr(
        mail_transport, "_consultar", lambda d, t: ['"v=STSv1; id=1"'] if "_mta-sts" in d else []
    )
    monkeypatch.setattr(mail_transport, "fetch", lambda d, ruta="/", **k: _resp("mode: enforce"))
    fs = mail_transport.analizar("ej.com")
    assert _nivel(fs, "MTA-STS") is Risk.OK


def test_mta_sts_ausente_es_bajo(monkeypatch):
    monkeypatch.setattr(mail_transport, "_consultar", lambda d, t: [])
    monkeypatch.setattr(mail_transport, "fetch", lambda d, ruta="/", **k: _resp(status=404))
    fs = mail_transport.analizar("ej.com")
    assert _nivel(fs, "MTA-STS") is Risk.BAJO


def test_mta_sts_testing_es_info(monkeypatch):
    monkeypatch.setattr(
        mail_transport, "_consultar", lambda d, t: ['"v=STSv1; id=1"'] if "_mta-sts" in d else []
    )
    monkeypatch.setattr(mail_transport, "fetch", lambda d, ruta="/", **k: _resp("mode: testing"))
    fs = mail_transport.analizar("ej.com")
    assert _nivel(fs, "MTA-STS") is Risk.INFO


def test_sin_tls_rpt_es_info(monkeypatch):
    monkeypatch.setattr(mail_transport, "_consultar", lambda d, t: [])
    monkeypatch.setattr(mail_transport, "fetch", lambda d, ruta="/", **k: _resp(status=404))
    fs = mail_transport.analizar("ej.com")
    assert _nivel(fs, "TLS-RPT") is Risk.INFO
