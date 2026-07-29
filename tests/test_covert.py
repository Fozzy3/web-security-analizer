"""Tests del canal encubierto en IP ID: codificación, decodificación y detección."""

from __future__ import annotations

import random

from webvulnscanner.covert import detector, ipid, mitigador
from webvulnscanner.models import Risk

# ── codificación / decodificación (round-trip) ───────────────


def test_round_trip():
    for datos in (b"hola", b"a", b"", b"mensaje secreto de longitud impar!", bytes(range(256))):
        assert ipid.decodificar(ipid.codificar(datos)) == datos


def test_ip_ids_en_rango_16bit():
    ids = ipid.codificar(b"password=admin123")
    assert all(0 <= v <= 65535 for v in ids)


def test_decodificar_ruido_sin_marco_es_none():
    random.seed(1)
    ruido = [random.randint(0, 65535) for _ in range(50)]
    assert ipid.decodificar(ruido) is None


# ── detección ────────────────────────────────────────────────


def test_detecta_canal_por_contenido():
    ids = ipid.codificar(b"exfil: clave secreta")
    fs = detector.analizar(ids)
    assert fs and fs[0].riesgo is Risk.ALTO
    assert "recuperado" in fs[0].hallazgo.lower()


def test_detecta_ip_id_secuencial():
    ids = list(range(1000, 1100))  # contador incremental
    fs = detector.analizar(ids)
    assert fs and "secuencial" in fs[0].hallazgo.lower() and fs[0].riesgo is Risk.MEDIO


def test_trafico_aleatorio_legitimo_no_reporta():
    random.seed(42)
    ids = [random.randint(0, 65535) for _ in range(500)]  # IP ID aleatorio (stack moderno)
    assert detector.analizar(ids) == []


def test_entropia_uniforme_mayor_que_sesgada():
    uniforme = list(range(256))
    sesgada = [0] * 200 + [1] * 56
    assert detector.entropia(uniforme) > detector.entropia(sesgada)


# ── mitigación ───────────────────────────────────────────────


def test_mitigacion_destruye_el_canal():
    ids = ipid.codificar(b"dato exfiltrado")
    assert ipid.decodificar(ids) == b"dato exfiltrado"  # antes: canal activo
    normalizados = mitigador.normalizar(ids)
    assert ipid.decodificar(normalizados) is None  # después: canal destruido


def test_id_aleatorio_en_rango():
    assert all(0 <= mitigador.id_aleatorio() <= 65535 for _ in range(50))


# ── B1: campos genéricos (TTL 8 bits, ISN 32 bits) ───────────


def test_round_trip_multi_campo():
    from webvulnscanner.covert import campos

    for bits in (8, 16, 32):
        assert campos.decodificar(campos.codificar(b"secreto", bits), bits) == b"secreto"


def test_detecta_covert_en_isn_32bit():
    from webvulnscanner.covert import campos

    isns = campos.codificar(b"exfil por ISN", 32)
    fs = detector.analizar(isns, bits=32)
    assert fs and fs[0].riesgo is Risk.ALTO


def test_ancho_no_soportado_lanza():
    import pytest

    from webvulnscanner.covert import campos

    with pytest.raises(ValueError, match="no soportado"):
        campos.codificar(b"x", 13)
