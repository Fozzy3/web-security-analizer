"""Codificación genérica de un canal encubierto en un campo de cabecera de N bits.

Generaliza el caso del IP ID (16 bits) a cualquier campo alineado a byte:
    TTL = 8 bits · IP ID = 16 bits · TCP ISN = 32 bits
El marco es el mismo: [MAGIC 2B][LONGITUD 2B][DATOS][padding al ancho del campo].
Puro y testeable (sin red).
"""

from __future__ import annotations

_MAGIC = b"\xc0\xde"

# Campos soportados (nombre → bits).
CAMPOS = {"ttl": 8, "ipid": 16, "isn": 32}


def _nbytes(bits: int) -> int:
    if bits <= 0 or bits % 8:
        raise ValueError(f"ancho de campo no soportado: {bits} bits (usar múltiplos de 8)")
    return bits // 8


def codificar(datos: bytes, bits: int = 16) -> list[int]:
    """Convierte `datos` en valores de un campo de `bits` bits."""
    nb = _nbytes(bits)
    marco = _MAGIC + len(datos).to_bytes(2, "big") + datos
    if len(marco) % nb:
        marco += b"\x00" * (nb - len(marco) % nb)
    return [int.from_bytes(marco[i : i + nb], "big") for i in range(0, len(marco), nb)]


def decodificar(valores: list[int], bits: int = 16) -> bytes | None:
    """Recupera los datos ocultos de una secuencia de valores, o None."""
    nb = _nbytes(bits)
    crudo = b"".join(v.to_bytes(nb, "big") for v in valores)
    i = crudo.find(_MAGIC)
    if i < 0 or len(crudo) < i + 4:
        return None
    n = int.from_bytes(crudo[i + 2 : i + 4], "big")
    datos = crudo[i + 4 : i + 4 + n]
    return datos if len(datos) == n else None
