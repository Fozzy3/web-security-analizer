"""Mitigación del canal encubierto en IP ID: aleatorizar el campo.

La primitiva (`id_aleatorio`, `normalizar`) es pura y testeable: reescribir el IP ID
con valores aleatorios destruye el canal encubierto sin romper el tráfico. La
aplicación inline en un gateway usa netfilterqueue (NFQUEUE); si no está disponible,
se documenta cómo habilitarla.
"""

from __future__ import annotations

import logging
import secrets

log = logging.getLogger("webvulnscanner.covert.mitigador")

try:
    from netfilterqueue import NetfilterQueue

    _NFQ = True
except Exception:  # noqa: BLE001
    _NFQ = False


def disponible() -> bool:
    return _NFQ


def id_aleatorio() -> int:
    """Un IP ID aleatorio de 16 bits (criptográficamente aleatorio)."""
    return secrets.randbelow(65536)


def normalizar(ids: list[int]) -> list[int]:
    """Reemplaza cada IP ID por uno aleatorio (destruye el canal encubierto)."""
    return [id_aleatorio() for _ in ids]


def ejecutar(cola: int = 1) -> None:  # pragma: no cover - requiere root + NFQUEUE + iptables
    """Corre un gateway NFQUEUE que aleatoriza el IP ID de cada paquete.

    Requisitos (Linux, como root):
        apt install libnetfilter-queue-dev && pip install netfilterqueue
        iptables -I FORWARD -j NFQUEUE --queue-num 1
    """
    if not _NFQ:
        raise RuntimeError(
            "netfilterqueue no instalado. En Linux: 'apt install libnetfilter-queue-dev' + "
            "'pip install netfilterqueue', y 'iptables -I FORWARD -j NFQUEUE --queue-num 1'."
        )
    from scapy.all import IP

    def _cb(paquete):
        p = IP(paquete.get_payload())
        p.id = id_aleatorio()
        del p.chksum  # forzar recálculo del checksum
        paquete.set_payload(bytes(p))
        paquete.accept()

    nfq = NetfilterQueue()
    nfq.bind(cola, _cb)
    log.info("  [+] Mitigación activa: aleatorizando IP ID en la cola NFQUEUE %d", cola)
    try:
        nfq.run()
    finally:
        nfq.unbind()
