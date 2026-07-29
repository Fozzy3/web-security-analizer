"""Canal encubierto por temporización (Timing Covert Channel).

La información se codifica en el retardo entre paquetes: `t0` = bit 0, `t1` = bit 1.
No modifica ninguna cabecera ni payload, así que es invisible a la inspección de
contenido. Se detecta por la distribución **bimodal** de los retardos (dos grupos
apretados en vez de la variación natural del tráfico). Mitigación: normalizar los
retardos a una tasa constante.

Núcleo puro y testeable (sin red).
"""

from __future__ import annotations

import statistics

from webvulnscanner.models import Finding, Risk

_MAGIC = b"\xc0\xde"


def _a_bits(datos: bytes) -> list[int]:
    return [(b >> (7 - i)) & 1 for b in datos for i in range(8)]


def _desde_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def codificar(datos: bytes, *, t0: float = 0.1, t1: float = 0.2) -> list[float]:
    """Devuelve la lista de retardos (s) que codifican `datos` bit a bit."""
    marco = _MAGIC + len(datos).to_bytes(2, "big") + datos
    return [t1 if bit else t0 for bit in _a_bits(marco)]


def decodificar(retardos: list[float], *, umbral: float | None = None) -> bytes | None:
    """Recupera los datos de una lista de retardos, o None si no hay marco."""
    if not retardos:
        return None
    u = umbral if umbral is not None else (min(retardos) + max(retardos)) / 2
    bits = [1 if d >= u else 0 for d in retardos]
    crudo = _desde_bits(bits)
    i = crudo.find(_MAGIC)
    if i < 0 or len(crudo) < i + 4:
        return None
    n = int.from_bytes(crudo[i + 2 : i + 4], "big")
    datos = crudo[i + 4 : i + 4 + n]
    return datos if len(datos) == n else None


def es_bimodal(retardos: list[float], *, separacion_min: float = 3.0) -> bool:
    """True si los retardos se agrupan en dos modos claros (firma de timing channel)."""
    if len(retardos) < 8:
        return False
    s = sorted(retardos)
    gap, idx = max((s[i + 1] - s[i], i) for i in range(len(s) - 1))
    a, b = s[: idx + 1], s[idx + 1 :]
    if len(a) < 2 or len(b) < 2:
        return False
    dispersion = (statistics.pstdev(a) + statistics.pstdev(b)) / 2 or 1e-9
    return gap / dispersion >= separacion_min


def normalizar(retardos: list[float], *, tasa: float | None = None) -> list[float]:
    """Mitigación: reemplaza los retardos por uno constante (destruye el canal)."""
    if not retardos:
        return []
    t = tasa if tasa is not None else statistics.median(retardos)
    return [t] * len(retardos)


def analizar(retardos: list[float]) -> list[Finding]:
    if not retardos:
        return []
    datos = decodificar(retardos)
    if datos is not None:
        muestra = datos[:40].decode("latin-1", "replace")
        return [
            Finding(
                "Covert Channel",
                "Canal encubierto por temporización (mensaje recuperado)",
                Risk.ALTO,
                f"Se recuperó un mensaje de {len(datos)} bytes codificado en el retardo entre "
                "paquetes. Mitigación: normalizar la tasa de envío (traffic shaping).",
                evidencia=f"{muestra!r}",
                owasp="A02:2025",
            )
        ]
    if es_bimodal(retardos):
        return [
            Finding(
                "Covert Channel",
                "Distribución bimodal de retardos (posible timing channel)",
                Risk.MEDIO,
                "Los retardos entre paquetes se agrupan en dos modos claros, en vez de la variación "
                "natural del tráfico: posible canal encubierto por temporización. Normalice la tasa.",
                evidencia=f"{len(retardos)} retardos, patrón bimodal",
                owasp="A02:2025",
            )
        ]
    return []
