"""Detección de canales encubiertos en el campo IP ID.

Analiza una secuencia de IP IDs (extraída de una captura) y decide si es tráfico
legítimo o un canal encubierto, con dos señales:

  1. Contenido: si la secuencia decodifica un marco válido → canal confirmado.
  2. Estadística: entropía del campo y grado de secuencialidad. Un IP ID que
     "debería" ser aleatorio pero lleva datos estructurados tiene entropía baja;
     uno secuencial delata un contador (zombie para Idle Scan).

Todo es puro y testeable. La clasificación por ML (scikit-learn) vive en `ml.py`.
"""

from __future__ import annotations

import math
from collections import Counter

from webvulnscanner.covert import campos
from webvulnscanner.models import Finding, Risk

_UMBRAL_ENTROPIA = 6.5  # bits/byte; ~8 = aleatorio real, texto/estructura < 6.5
_UMBRAL_SECUENCIAL = 0.9  # fracción de saltos pequeños crecientes → contador
_MIN_MUESTRAS_ENTROPIA = 40  # con menos IP IDs la entropía no es fiable (falsos positivos)


def entropia(valores: list[int]) -> float:
    """Entropía de Shannon (bits por símbolo) de una lista de valores."""
    if not valores:
        return 0.0
    n = len(valores)
    return -sum((c / n) * math.log2(c / n) for c in Counter(valores).values())


def _bytes_de(ids: list[int], bits: int = 16) -> list[int]:
    nb = bits // 8
    return list(b"".join(v.to_bytes(nb, "big") for v in ids))


def ratio_secuencial(ids: list[int]) -> float:
    """Fracción de IP IDs consecutivos que crecen en un delta pequeño (1-8)."""
    if len(ids) < 2:
        return 0.0
    inc = sum(1 for a, b in zip(ids, ids[1:], strict=False) if 0 < (b - a) % 65536 <= 8)
    return inc / (len(ids) - 1)


def caracteristicas(ids: list[int], bits: int = 16) -> dict[str, float]:
    """Vector de características para heurística o modelo ML."""
    return {
        "entropia_byte": entropia(_bytes_de(ids, bits)),
        "ratio_secuencial": ratio_secuencial(ids),
        "n": float(len(ids)),
    }


def analizar(ids: list[int], bits: int = 16) -> list[Finding]:
    """Devuelve hallazgos sobre una secuencia de valores de un campo de `bits` bits."""
    if not ids:
        return []

    # 1. Señal de contenido: ¿decodifica un mensaje oculto?
    datos = campos.decodificar(ids, bits)
    if datos is not None:
        muestra = datos[:40].decode("latin-1", "replace")
        return [
            Finding(
                "Covert Channel",
                "Canal encubierto en el campo IP ID (mensaje recuperado)",
                Risk.ALTO,
                f"Se recuperó un mensaje oculto de {len(datos)} bytes codificado en el campo IP "
                "Identification. El tráfico cumple el estándar TCP/IP pero exfiltra datos. "
                "Mitigación: normalizar/aleatorizar el IP ID en el gateway (NFQUEUE).",
                evidencia=f"{muestra!r}",
                owasp="A02:2025",
            )
        ]

    # 2. Señal estadística.
    car = caracteristicas(ids, bits)
    if car["ratio_secuencial"] >= _UMBRAL_SECUENCIAL:
        return [
            Finding(
                "Covert Channel",
                "IP ID secuencial (contador global)",
                Risk.MEDIO,
                "El campo IP ID es un contador secuencial: el host es usable como 'zombie' para "
                "Idle/Zombie Scan y facilita la predicción de secuencias. Aleatorice el IP ID.",
                evidencia=f"ratio_secuencial={car['ratio_secuencial']:.2f}",
                owasp="A02:2025",
            )
        ]
    if car["n"] >= _MIN_MUESTRAS_ENTROPIA and car["entropia_byte"] < _UMBRAL_ENTROPIA:
        return [
            Finding(
                "Covert Channel",
                "Distribución anómala del IP ID (posible canal encubierto)",
                Risk.MEDIO,
                f"La entropía del campo IP ID ({car['entropia_byte']:.1f} bits/byte) es baja para un "
                "valor que debería ser aleatorio: posible canal encubierto con datos estructurados. "
                "Verifique con captura y aleatorice el IP ID.",
                evidencia=f"entropia={car['entropia_byte']:.2f} bits/byte",
                owasp="A02:2025",
            )
        ]
    return []
