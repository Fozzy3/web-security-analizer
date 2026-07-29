"""Canal encubierto en el campo IP Identification (16 bits).

Codifica datos arbitrarios en el campo IP ID de una serie de paquetes. El campo
es de 16 bits y normalmente se considera "ruido" (aleatorio o un contador), lo que
lo hace un portador sigiloso.

Formato del marco (para que el receptor sincronice):
    [MAGIC 2B = 0xC0DE][LONGITUD 2B big-endian][DATOS N bytes][padding a par]
Cada 16 bits del marco → un valor de IP ID. Todo aquí es puro (sin red), para
poder probar codificación/decodificación de forma determinista.
"""

from __future__ import annotations

from webvulnscanner.covert import campos


def codificar(datos: bytes) -> list[int]:
    """Convierte `datos` en una lista de valores de IP ID (16 bits)."""
    return campos.codificar(datos, 16)


def decodificar(ids: list[int]) -> bytes | None:
    """Recupera los datos ocultos de una secuencia de IP IDs, o None si no hay marco."""
    return campos.decodificar(ids, 16)
