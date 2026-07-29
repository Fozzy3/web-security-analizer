"""Tests del módulo TLS: clasificación de certificados y orquestación de analizar().

Los handshakes se sustituyen por dobles: aquí interesa la lógica de decisión
(umbrales de expiración, versiones obsoletas, corte temprano sin TLS).
"""

from __future__ import annotations

import datetime

import pytest

from webvulnscanner.models import Risk
from webvulnscanner.modules import tls


def _cert(dias: int | None = 365, **extra):
    """Certificado estilo getpeercert() que expira dentro de `dias`."""
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"), ("IP Address", "1.2.3.4")),
    }
    if dias is not None:
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=dias, hours=1)
        cert["notAfter"] = exp.strftime("%b %d %H:%M:%S %Y GMT")
    cert.update(extra)
    return cert


def _nivel(findings, fragmento) -> Risk:
    return next(f.riesgo for f in findings if fragmento in f.hallazgo)


# ── expiración ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("dias", "esperado"),
    [
        (-5, Risk.ALTO),  # expirado
        (10, Risk.ALTO),  # < 30
        (60, Risk.MEDIO),  # < 90
        (200, Risk.OK),  # holgado
    ],
)
def test_umbral_expiracion(dias, esperado):
    assert _nivel(tls._findings_cert(_cert(dias)), "expira") is esperado


def test_sin_not_after_no_reporta_expiracion():
    findings = tls._findings_cert(_cert(dias=None))
    assert not any("expira" in f.hallazgo for f in findings)
    assert len(findings) == 1  # solo el informativo de CN/emisor


def test_fecha_corrupta_no_revienta():
    """Un notAfter con formato raro degrada, no aborta el módulo."""
    findings = tls._findings_cert(_cert(dias=None, notAfter="fecha rara"))
    assert not any("expira" in f.hallazgo for f in findings)


# ── sujeto / emisor / SAN ────────────────────────────────────


def test_cn_emisor_y_san():
    (info,) = [f for f in tls._findings_cert(_cert(dias=None)) if f.riesgo is Risk.INFO]
    assert "CN=example.com" in info.hallazgo
    assert "Let's Encrypt" in info.hallazgo
    assert "2 nombre(s) SAN" in info.descripcion  # la entrada IP Address no cuenta
    assert info.evidencia == "example.com, www.example.com"


def test_cert_vacio_usa_placeholders():
    (info,) = tls._findings_cert({})
    assert "CN=—" in info.hallazgo


# ── analizar(): orquestación ─────────────────────────────────


@pytest.fixture
def sin_red(monkeypatch):
    """Neutraliza todas las llamadas de red del módulo."""
    monkeypatch.setattr(tls, "_probar_version", lambda d, v: None)
    monkeypatch.setattr(tls, "_cipher_debil", lambda d: None)
    monkeypatch.setattr(tls, "_analizar_certificado", lambda d: [])
    monkeypatch.setattr(tls, "_analizar_clave", lambda d: [])
    monkeypatch.setattr(tls, "_redireccion_https", lambda d: None)


def test_sin_ninguna_version_corta_temprano(sin_red, monkeypatch):
    llamado = []
    monkeypatch.setattr(tls, "_cipher_debil", lambda d: llamado.append(d))
    (f,) = tls.analizar("example.com")
    assert f.riesgo is Risk.ALTO
    assert "No se pudo negociar" in f.hallazgo
    assert llamado == []  # no sigue sondeando un puerto sin TLS


def _acepta(*versiones: str):
    """Doble de _probar_version que solo acepta las versiones indicadas."""
    return lambda dominio, v: v.name if v.name in versiones else None


def test_versiones_obsoletas_generan_hallazgos(sin_red, monkeypatch):
    monkeypatch.setattr(tls, "_probar_version", _acepta("SSLv3", "TLSv1", "TLSv1_2"))
    findings = tls.analizar("example.com")
    obsoletos = {f.hallazgo for f in findings if "obsoleto aceptado" in f.hallazgo}
    assert obsoletos == {"Protocolo obsoleto aceptado: SSLv3", "Protocolo obsoleto aceptado: TLSv1.0"}
    assert _nivel(findings, "Protocolo obsoleto aceptado: SSLv3") is Risk.ALTO
    assert _nivel(findings, "Versiones TLS soportadas") is Risk.OK  # hay 1.2


def test_cliente_sin_soporte_no_concluye(sin_red, monkeypatch):
    """ "" significa que el OpenSSL local no ofrece la versión: no es un hallazgo."""
    monkeypatch.setattr(tls, "_probar_version", lambda d, v: "" if v.name.startswith("SSL") else None)
    (f,) = tls.analizar("example.com")
    assert "No se pudo negociar" in f.hallazgo


def test_solo_versiones_viejas_es_alto(sin_red, monkeypatch):
    monkeypatch.setattr(tls, "_probar_version", _acepta("TLSv1", "TLSv1_1"))
    findings = tls.analizar("example.com")
    assert _nivel(findings, "Versiones TLS soportadas") is Risk.ALTO


def test_cipher_debil_se_reporta(sin_red, monkeypatch):
    monkeypatch.setattr(tls, "_probar_version", _acepta("TLSv1_2"))
    monkeypatch.setattr(tls, "_cipher_debil", lambda d: "ECDHE-RSA-RC4-SHA")
    assert _nivel(tls.analizar("example.com"), "Cipher débil") is Risk.ALTO


@pytest.mark.parametrize("nombre", ["ECDHE-RSA-RC4-SHA", "DES-CBC3-SHA", "EXP-RC2-MD5", "ADH-AES256-SHA"])
def test_fragmentos_debiles_reconocidos(nombre):
    assert any(frag in nombre.upper() for frag in tls._DEBILES)


@pytest.mark.parametrize("nombre", ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-GCM-SHA256"])
def test_ciphers_fuertes_no_marcados(nombre):
    """Regresión: las suites AEAD de TLS 1.3 no son ciphers débiles."""
    assert not any(frag in nombre.upper() for frag in tls._DEBILES)
