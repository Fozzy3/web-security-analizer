"""Tests de detección de subdomain takeover con DNS simulado."""

import dns.resolver

from webvulnscanner.modules import subdomains


class _FakeCname:
    def __init__(self, target):
        self.target = target


def _resolver(cname_target=None, destino_resuelve=False):
    """Construye un fake de dns.resolver.resolve."""

    def fake(name, rtype, lifetime=4):
        if rtype == "CNAME":
            if cname_target is None:
                raise dns.resolver.NoAnswer
            return [_FakeCname(cname_target)]
        # rtype == "A": resolución del destino del CNAME
        if destino_resuelve:
            return ["1.2.3.4"]
        raise dns.resolver.NXDOMAIN

    return fake


def test_takeover_detecta_cname_colgante(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", _resolver("myapp.herokuapp.com.", destino_resuelve=False))
    assert subdomains.revisar_takeover("x.ej.com") == "myapp.herokuapp.com"


def test_no_takeover_si_destino_resuelve(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", _resolver("myapp.herokuapp.com.", destino_resuelve=True))
    assert subdomains.revisar_takeover("x.ej.com") is None


def test_no_takeover_si_cname_no_es_servicio(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", _resolver("interno.ej.com.", destino_resuelve=False))
    assert subdomains.revisar_takeover("x.ej.com") is None


def test_no_takeover_sin_cname(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", _resolver(cname_target=None))
    assert subdomains.revisar_takeover("x.ej.com") is None


def test_detectar_takeovers_genera_finding_alto(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", _resolver("gone.herokuapp.com.", destino_resuelve=False))
    fs = subdomains.detectar_takeovers(["a.ej.com", "b.ej.com"])
    assert fs and all(f.riesgo.value == "alto" for f in fs)
