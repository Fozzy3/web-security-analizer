"""Calificación global del objetivo a partir de sus hallazgos.

Modelo de deducción ponderada (estilo Mozilla Observatory / SSL Labs): se parte
de 100 y se descuenta por severidad, con una pequeña bonificación por buenas
prácticas confirmadas. El resultado es una nota A–F fácil de comunicar.
"""

from __future__ import annotations

from webvulnscanner.models import Risk, ScanResult

# Puntos que resta cada hallazgo según su nivel.
_PESO = {Risk.ALTO: 25, Risk.MEDIO: 10, Risk.BAJO: 3, Risk.INFO: 0, Risk.OK: 0}
_BONUS_OK = 2  # suma por cada buena práctica confirmada
_BONUS_MAX = 10  # tope de la bonificación

_LETRAS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (50, "E")]


def letra(puntaje: int) -> str:
    for umbral, ltr in _LETRAS:
        if puntaje >= umbral:
            return ltr
    return "F"


def calcular(result: ScanResult) -> tuple[str, int]:
    """Devuelve (letra, puntaje 0-100)."""
    conteo = result.conteo()
    penalizacion = sum(_PESO[nivel] * n for nivel, n in conteo.items())
    bonus = min(conteo[Risk.OK] * _BONUS_OK, _BONUS_MAX)
    puntaje = max(0, min(100, 100 - penalizacion + bonus))
    return letra(puntaje), puntaje


def resumen(result: ScanResult) -> str:
    """Línea legible: 'Nota: B (82/100)'."""
    ltr, pts = calcular(result)
    return f"Nota de seguridad: {ltr} ({pts}/100)"
