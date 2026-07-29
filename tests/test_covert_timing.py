"""Tests del canal encubierto por temporización (B2) y detección de anomalías (C1)."""

from __future__ import annotations

import random

from webvulnscanner.covert import ipid, ml, timing
from webvulnscanner.models import Risk

# ── B2: timing channel ───────────────────────────────────────


def test_round_trip_timing():
    for datos in (b"hola", b"exfil", b"clave=1234"):
        assert timing.decodificar(timing.codificar(datos)) == datos


def test_detecta_timing_por_contenido():
    fs = timing.analizar(timing.codificar(b"secreto por tiempo"))
    assert fs and fs[0].riesgo is Risk.ALTO


def test_detecta_bimodalidad_sin_marco():
    # dos modos claros (0.1 y 0.2) sin marco válido → MEDIO
    random.seed(3)
    retardos = [random.choice([0.10, 0.20]) + random.uniform(-0.003, 0.003) for _ in range(80)]
    assert timing.es_bimodal(retardos)


def test_trafico_normal_no_es_bimodal():
    random.seed(5)
    retardos = [random.expovariate(1 / 0.15) for _ in range(200)]  # variación natural
    assert not timing.es_bimodal(retardos)


def test_mitigacion_timing_destruye_canal():
    retardos = timing.codificar(b"dato oculto")
    assert timing.decodificar(retardos) == b"dato oculto"
    normalizados = timing.normalizar(retardos)
    assert timing.decodificar(normalizados) is None
    assert timing.analizar(normalizados) == []


# ── C1: detección de anomalías (IsolationForest) ─────────────


def test_anomalias_detecta_covert_como_atipico():
    if not ml.disponible():
        return
    random.seed(11)
    # entrena SOLO con tráfico legítimo (IP ID aleatorio)
    legit = [[random.randint(0, 65535) for _ in range(40)] for _ in range(80)]
    modelo = ml.entrenar_anomalias(legit)
    # un canal encubierto (baja entropía / estructurado) debería salir anómalo
    covert = ipid.codificar(b"AAAAAAAAAAAAAAAAAAAAAAAA")
    assert ml.es_anomalo(modelo, covert)
