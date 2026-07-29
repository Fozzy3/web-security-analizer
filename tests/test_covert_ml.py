"""Test del clasificador ML de canales encubiertos (si scikit-learn está)."""

from __future__ import annotations

import random

from webvulnscanner.covert import ipid, ml


def _muestras_covert(n):
    palabras = [b"password", b"secreto", b"exfil data", b"clave=1234", b"token abc"]
    return [ipid.codificar(random.choice(palabras) * random.randint(1, 4)) for _ in range(n)]


def _muestras_legit(n):
    out = []
    for _ in range(n):
        if random.random() < 0.5:
            out.append([random.randint(0, 65535) for _ in range(40)])  # aleatorio
        else:
            base = random.randint(0, 60000)
            out.append([base + i for i in range(40)])  # secuencial
    return out


def test_clasificador_distingue_covert_de_legitimo():
    if not ml.disponible():
        return  # sin scikit-learn; no aplica
    random.seed(7)
    modelo = ml.entrenar(_muestras_covert(60), _muestras_legit(60))
    # held-out
    p_covert = ml.probabilidad_covert(modelo, ipid.codificar(b"mensaje oculto de prueba"))
    p_legit = ml.probabilidad_covert(modelo, [random.randint(0, 65535) for _ in range(40)])
    assert p_covert > 0.5 > p_legit
