"""Módulo opcional: inteligencia de Shodan sobre la IP del objetivo.

100% pasivo: consulta la base de datos de Shodan (no toca al objetivo).
Con `SHODAN_API_KEY` usa la Host API (datos ricos); sin key cae a la API
**gratuita InternetDB** (sin registro: puertos, CVEs y hostnames por IP).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
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


_INTERNETDB = "https://internetdb.shodan.io/{ip}"
# InternetDB rechaza el User-Agent por defecto de urllib con 403; usar uno de navegador.
_UA_IDB = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"


def _internetdb(ip: str, timeout: int) -> dict:
    """API gratuita InternetDB de Shodan (sin API key). 404 = IP no indexada."""
    req = urllib.request.Request(
        _INTERNETDB.format(ip=urllib.parse.quote(ip)), headers={"User-Agent": _UA_IDB}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_vacio": True}  # IP no indexada: sin datos (no es error)
        log.info("  [-] InternetDB HTTP %s", e.code)
        return {}
    except Exception as e:  # noqa: BLE001
        log.info("  [-] InternetDB no respondió: %s", e)
        return {}


def analizar(ip: str | None, *, timeout: int = 15) -> list[Finding]:
    """Con SHODAN_API_KEY usa la Host API; sin key, la API gratuita InternetDB."""
    if not ip:
        return []
    key = os.environ.get("SHODAN_API_KEY")
    if key:
        datos = cached_json(f"shodan:{ip}", _TTL, lambda: _descargar(ip, key, timeout))
        return _findings_host(ip, datos)
    datos = cached_json(f"shodan-idb:{ip}", _TTL, lambda: _internetdb(ip, timeout))
    return _findings_idb(ip, datos)


def _finding_puertos(ip: str, puertos: list[int], detalle: str) -> Finding:
    return Finding(
        "Shodan",
        f"Shodan: {len(puertos)} puertos indexados",
        Risk.INFO,
        detalle,
        referencia=f"https://www.shodan.io/host/{ip}",
        evidencia=", ".join(map(str, sorted(puertos))),
    )


def _finding_vulns(ip: str, vulns: list[str], fuente: str) -> Finding:
    log.info("  [!] Shodan reporta %d CVEs para %s", len(vulns), ip)
    return Finding(
        "Shodan",
        f"Shodan reporta {len(vulns)} CVE(s) conocidos en la IP",
        Risk.ALTO,
        f"Vulnerabilidades asociadas por Shodan ({fuente}): " + ", ".join(sorted(vulns)[:15]),
        referencia=f"https://www.shodan.io/host/{ip}",
        evidencia=", ".join(sorted(vulns)),
    )


def _findings_host(ip: str, datos: dict) -> list[Finding]:
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
            _finding_puertos(
                ip,
                puertos,
                f"Origen: {org or 'desconocido'}. Puertos vistos por Shodan: "
                f"{', '.join(map(str, sorted(puertos)))}. Histórico de exposición del host.",
            )
        )
    if datos.get("vulns"):
        findings.append(_finding_vulns(ip, datos["vulns"], "Host API"))
    return findings


def _findings_idb(ip: str, datos: dict) -> list[Finding]:
    if not datos or datos.get("_vacio"):
        return []  # IP no indexada o sin red: silencioso
    findings: list[Finding] = []
    puertos = datos.get("ports", [])
    hostnames = datos.get("hostnames", [])
    if puertos:
        extra = f" · hostnames: {', '.join(hostnames[:5])}" if hostnames else ""
        findings.append(
            _finding_puertos(
                ip,
                puertos,
                f"Puertos vistos por Shodan: {', '.join(map(str, sorted(puertos)))}{extra}. "
                "Consulta gratuita (InternetDB, sin API key).",
            )
        )
    if datos.get("vulns"):
        findings.append(_finding_vulns(ip, datos["vulns"], "InternetDB"))
    return findings
