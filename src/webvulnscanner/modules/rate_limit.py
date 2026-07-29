"""Fase V: consumo de recursos / rate-limit (API4:2023). Activo suave, gateado.

Verifica si el objetivo aplica rate-limiting. NUNCA es un DoS: una ráfaga acotada
(`--rl-burst`, por defecto pequeña) que respeta el throttle de la sesión; el
objetivo es medir la AUSENCIA de control, no agotar recursos.
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import request

log = logging.getLogger("webvulnscanner.rate_limit")

_HEADERS_RL = ("x-ratelimit-remaining", "x-rate-limit-remaining", "ratelimit-remaining", "retry-after")


def _tiene_rate_limit(r) -> bool:
    if r.status == 429:
        return True
    return any(r.header(h) is not None for h in _HEADERS_RL)


def analizar(dominio: str, *, burst: int = 12) -> list[Finding]:
    for _ in range(burst):
        r = request(dominio, "/")
        if r is not None and _tiene_rate_limit(r):
            return []  # hay control de tasa
    log.info("  [!] Sin rate-limiting observado tras %d peticiones", burst)
    return [
        Finding(
            "Rate Limiting",
            "Ausencia de rate-limiting",
            Risk.BAJO,
            f"El objetivo respondió a {burst} peticiones seguidas sin 429 ni cabeceras de límite: "
            "habilita abuso de recursos y fuerza bruta. Aplique rate-limiting por IP/credencial.",
            owasp="A02:2025",
        )
    ]
