"""Módulo 6: Enumeración pasiva de subdominios vía Certificate Transparency.

Consulta crt.sh (logs públicos de CT). No toca al objetivo: lee certificados
ya emitidos y publicados. Amplía la superficie de ataque visible.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import USER_AGENT

log = logging.getLogger("webvulnscanner.subdomains")

_CRT_SH = "https://crt.sh/?q=%25.{dominio}&output=json"


def consultar_crtsh(dominio: str, *, timeout: int = 20) -> set[str]:
    """Devuelve el conjunto de subdominios vistos en CT logs para el dominio."""
    url = _CRT_SH.format(dominio=urllib.parse.quote(dominio))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            datos = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        log.info("  [-] crt.sh no respondió: %s", e)
        return set()

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
        return [Finding("Subdominios", "Sin subdominios encontrados en CT logs", Risk.INFO,
                        "No se hallaron subdominios en Certificate Transparency.")]

    ordenados = sorted(subs)
    log.info("  [+] %d subdominios en CT logs", len(ordenados))
    muestra = ", ".join(ordenados[:15]) + (" …" if len(ordenados) > 15 else "")
    return [Finding(
        "Subdominios", f"{len(ordenados)} subdominios descubiertos vía CT logs", Risk.INFO,
        f"Subdominios publicados en certificados: {muestra}. Cada uno amplía la superficie "
        "de ataque; revise que ninguno exponga entornos internos (dev, staging, admin).",
        referencia="https://crt.sh", evidencia="\n".join(ordenados))]
