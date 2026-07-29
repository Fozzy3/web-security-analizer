"""Receptor del canal encubierto: captura paquetes y extrae el IP ID.

Usa scapy sniff (requiere root). Devuelve la lista de IP IDs capturados, que luego
`ipid.decodificar` reconstruye. Solo para laboratorio autorizado.
"""

from __future__ import annotations

import logging

log = logging.getLogger("webvulnscanner.covert.receptor")

try:
    from scapy.all import IP, sniff

    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False


def disponible() -> bool:
    return _SCAPY


def capturar(
    cantidad: int, *, filtro: str = "icmp", timeout: int = 30, iface: str | None = None
) -> list[int]:
    """Captura `cantidad` paquetes y devuelve sus IP IDs (en orden de llegada)."""
    if not _SCAPY:
        raise RuntimeError("scapy no instalado (extra 'netlab') o sin permisos de red")
    paquetes = sniff(filter=filtro, count=cantidad, timeout=timeout, iface=iface)
    ids = [p[IP].id for p in paquetes if p.haslayer(IP)]
    log.info("  [+] Capturados %d IP IDs", len(ids))
    return ids
