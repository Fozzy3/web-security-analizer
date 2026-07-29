"""Clasificador ML de canales encubiertos en IP ID (scikit-learn, opcional).

La parte de "IA" del taller: en vez de umbrales fijos, entrena un modelo sobre las
características estadísticas (entropía, secuencialidad) para distinguir tráfico
legítimo de un canal encubierto. Degradación elegante: sin scikit-learn, se usa la
heurística de `detector`.
"""

from __future__ import annotations

from webvulnscanner.covert import detector

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier

    _SKLEARN = True
except Exception:  # noqa: BLE001
    _SKLEARN = False

_FEATS = ("entropia_byte", "ratio_secuencial")


def disponible() -> bool:
    return _SKLEARN


def _vector(ids: list[int]) -> list[float]:
    c = detector.caracteristicas(ids)
    return [c[f] for f in _FEATS]


def entrenar(covert: list[list[int]], legit: list[list[int]]):
    """Entrena un RandomForest con secuencias etiquetadas. Devuelve el modelo."""
    if not _SKLEARN:
        raise RuntimeError("scikit-learn no instalado (extra 'netlab')")
    x = [_vector(s) for s in covert] + [_vector(s) for s in legit]
    y = [1] * len(covert) + [0] * len(legit)
    return RandomForestClassifier(n_estimators=60, random_state=0).fit(x, y)


def probabilidad_covert(modelo, ids: list[int]) -> float:
    """Probabilidad (0-1) de que la secuencia sea un canal encubierto."""
    return float(modelo.predict_proba([_vector(ids)])[0][1])


def entrenar_anomalias(legit: list[list[int]]):
    """Entrena un IsolationForest SOLO con tráfico legítimo (no supervisado).

    Útil cuando no hay muestras de ataque: detecta cualquier secuencia que se
    aparte de lo normal (canales encubiertos cifrados, low-and-slow…).
    """
    if not _SKLEARN:
        raise RuntimeError("scikit-learn no instalado (extra 'netlab')")
    x = [_vector(s) for s in legit]
    return IsolationForest(contamination="auto", random_state=0).fit(x)


def es_anomalo(modelo, ids: list[int]) -> bool:
    """True si la secuencia es anómala respecto al tráfico legítimo aprendido."""
    return int(modelo.predict([_vector(ids)])[0]) == -1
