"""Módulo opcional: inteligencia de Shodan sobre la IP del objetivo.

100% pasivo: consulta la base de datos de Shodan (no toca al objetivo). Se
activa solo si existe la variable de entorno SHODAN_API_KEY; si no, se omite
en silencio. Requiere plan de Shodan con acceso a la Host API.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
import urllib.request

from webvulnscanner.cache import cached_json
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import USER_AGENT

log = logging.getLogger("webvulnscanner.shodan")

_HOST = "https://api.shodan.io/shodan/host/{ip}?key={key}"
_TTL = 43_200  # 12 h


def _descargar(ip: str, key: str, timeout: int) -> dict:
    url = _HOST.format(ip=urllib.parse.quote(ip), key=urllib.parse.quote(key))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        log.info("  [-] Shodan no respondió: %s", e)
        return {}


def analizar(ip: str | None, *, timeout: int = 15) -> list[Finding]:
    key = os.environ.get("SHODAN_API_KEY")
    if not key or not ip:
        return []  # sin API key o sin IP: módulo inactivo (silencioso)

    datos = cached_json(f"shodan:{ip}", _TTL, lambda: _descargar(ip, key, timeout))
    if not datos or "error" in datos:
        return [
            Finding(
                "Shodan",
                "Sin datos de Shodan para la IP",
                Risk.INFO,
                "Shodan no devolvió información (IP no indexada, plan sin acceso o error).",
            )
        ]

    findings: list[Finding] = []
    org = datos.get("org") or datos.get("isp")
    puertos = datos.get("ports", [])
    if org or puertos:
        findings.append(
            Finding(
                "Shodan",
                f"Shodan: {org or 'org desconocida'} — {len(puertos)} puertos indexados",
                Risk.INFO,
                f"Puertos vistos por Shodan: {', '.join(map(str, sorted(puertos)))}. "
                "Refleja el histórico de exposición del host.",
                referencia=f"https://www.shodan.io/host/{ip}",
                evidencia=", ".join(map(str, sorted(puertos))),
            )
        )

    vulns = datos.get("vulns", [])
    if vulns:
        log.info("  [!] Shodan reporta %d CVEs para %s", len(vulns), ip)
        findings.append(
            Finding(
                "Shodan",
                f"Shodan reporta {len(vulns)} CVE(s) conocidos en la IP",
                Risk.ALTO,
                "Vulnerabilidades asociadas por Shodan: " + ", ".join(sorted(vulns)[:15]),
                referencia=f"https://www.shodan.io/host/{ip}",
                evidencia=", ".join(sorted(vulns)),
            )
        )
    return findings
