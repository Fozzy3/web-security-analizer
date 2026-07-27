"""Módulo 6: Enumeración pasiva de subdominios vía Certificate Transparency.

Consulta crt.sh (logs públicos de CT). No toca al objetivo: lee certificados
ya emitidos y publicados. Amplía la superficie de ataque visible.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
import urllib.request

from webvulnscanner.cache import cached_json
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import USER_AGENT

log = logging.getLogger("webvulnscanner.subdomains")

_CRT_SH = "https://crt.sh/?q=%25.{dominio}&output=json"
_TTL = 86_400  # 24 h: los certificados nuevos aparecen despacio
_REINTENTOS = 3  # crt.sh devuelve 404/502 intermitentes bajo carga


def _descargar_crtsh(dominio: str, timeout: int) -> list:
    url = _CRT_SH.format(dominio=urllib.parse.quote(dominio))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for intento in range(1, _REINTENTOS + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as e:  # noqa: BLE001
            log.info("  [-] crt.sh intento %d/%d falló: %s", intento, _REINTENTOS, e)
            if intento < _REINTENTOS:
                time.sleep(1.5 * intento)  # backoff lineal
    return []


def consultar_crtsh(dominio: str, *, timeout: int = 25, ttl: int = _TTL) -> set[str]:
    """Devuelve el conjunto de subdominios vistos en CT logs para el dominio."""
    datos = cached_json(f"crtsh:{dominio}", ttl, lambda: _descargar_crtsh(dominio, timeout))

    nombres: set[str] = set()
    for entrada in datos:
        for campo in ("name_value", "common_name"):
            valor = entrada.get(campo, "")
            for nombre in valor.split("\n"):
                nombre = nombre.strip().lower().lstrip("*.")
                if nombre.endswith(dominio) and nombre != dominio:
                    nombres.add(nombre)
    return nombres


def analizar(dominio: str) -> list[Finding]:
    subs = consultar_crtsh(dominio)
    if not subs:
        log.info("  [+] Sin subdominios en CT logs (o crt.sh no disponible)")
        return [
            Finding(
                "Subdominios",
                "Sin subdominios encontrados en CT logs",
                Risk.INFO,
                "No se hallaron subdominios en Certificate Transparency.",
            )
        ]

    ordenados = sorted(subs)
    log.info("  [+] %d subdominios en CT logs", len(ordenados))
    muestra = ", ".join(ordenados[:15]) + (" …" if len(ordenados) > 15 else "")
    return [
        Finding(
            "Subdominios",
            f"{len(ordenados)} subdominios descubiertos vía CT logs",
            Risk.INFO,
            f"Subdominios publicados en certificados: {muestra}. Cada uno amplía la superficie "
            "de ataque; revise que ninguno exponga entornos internos (dev, staging, admin).",
            referencia="https://crt.sh",
            evidencia="\n".join(ordenados),
        )
    ]
