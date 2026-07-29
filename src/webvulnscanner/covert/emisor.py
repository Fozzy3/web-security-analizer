"""Emisor del canal encubierto: envía paquetes con datos ocultos en el IP ID.

Usa scapy (requiere root/CAP_NET_RAW). Degradación elegante: sin scapy,
`disponible()` es False. Solo para laboratorio autorizado.
"""

from __future__ import annotations

import logging
import time

from webvulnscanner.covert import campos, timing

log = logging.getLogger("webvulnscanner.covert.emisor")

try:
    from scapy.all import ICMP, IP, TCP, send

    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False


def disponible() -> bool:
    return _SCAPY


def _paquete(destino: str, campo: str, valor: int):
    if campo == "ttl":
        return IP(dst=destino, ttl=valor) / ICMP()
    if campo == "isn":
        return IP(dst=destino) / TCP(dport=80, flags="S", seq=valor)
    return IP(dst=destino, id=valor) / ICMP()  # ipid (por defecto)


def enviar(destino: str, datos: bytes, *, campo: str = "ipid", intervalo: float = 0.05) -> int:
    """Envía `datos` ocultos en el campo indicado (ipid/ttl/isn). Devuelve nº de paquetes."""
    if not _SCAPY:
        raise RuntimeError("scapy no instalado (extra 'netlab') o sin permisos de red")
    bits = campos.CAMPOS.get(campo, 16)
    valores = campos.codificar(datos, bits)
    for v in valores:
        send(_paquete(destino, campo, v), verbose=0)
        time.sleep(intervalo)
    log.info("  [+] Enviados %d paquetes (%s) con datos ocultos a %s", len(valores), campo, destino)
    return len(valores)


def enviar_timing(destino: str, datos: bytes, *, t0: float = 0.1, t1: float = 0.2) -> int:
    """Envía `datos` ocultos en el retardo entre paquetes (timing channel)."""
    if not _SCAPY:
        raise RuntimeError("scapy no instalado (extra 'netlab') o sin permisos de red")
    retardos = timing.codificar(datos, t0=t0, t1=t1)
    for d in retardos:
        send(IP(dst=destino) / ICMP(), verbose=0)
        time.sleep(d)
    log.info("  [+] Enviados %d paquetes con timing channel a %s", len(retardos), destino)
    return len(retardos)
