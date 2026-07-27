"""Módulo 10: Correlación de CVEs (NVD).

Dado un producto y versión detectados (p.ej. de la cabecera Server), consulta
la API pública del NVD y reporta los CVEs más severos. Sin API key la NVD
limita a ~5 peticiones/30s; se hace una sola consulta por escaneo.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request

from webvulnscanner.cache import cached_json
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import USER_AGENT

log = logging.getLogger("webvulnscanner.cve")

_TTL = 21_600  # 6 h

# ponytail: keyword search (no CPE), puede traer falsos positivos de productos
# con nombre parecido. Techo conocido; subir a matching por CPE si se requiere precisión.
_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage=50"

# CVSS baseSeverity -> Risk
_SEVERIDAD = {"CRITICAL": Risk.ALTO, "HIGH": Risk.ALTO, "MEDIUM": Risk.MEDIO, "LOW": Risk.BAJO}


def _score(cve: dict) -> float:
    metrics = cve.get("metrics", {})
    for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(clave):
            return metrics[clave][0]["cvssData"].get("baseScore", 0.0)
    return 0.0


def _severidad(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for clave in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(clave):
            return metrics[clave][0]["cvssData"].get("baseSeverity", "MEDIUM")
    if metrics.get("cvssMetricV2"):
        return metrics["cvssMetricV2"][0].get("baseSeverity", "MEDIUM")
    return "MEDIUM"


def _descargar_nvd(producto: str, version: str, timeout: int) -> dict:
    q = urllib.parse.quote(f"{producto} {version}")
    req = urllib.request.Request(_NVD.format(q=q), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        log.info("  [-] NVD no respondió: %s", e)
        return {}


def consultar_nvd(
    producto: str, version: str, *, timeout: int = 25, limite: int = 5, ttl: int = _TTL
) -> list[dict]:
    """Devuelve una lista de dicts {id, score, severidad, resumen} ordenada por score."""
    datos = cached_json(f"nvd:{producto}:{version}", ttl, lambda: _descargar_nvd(producto, version, timeout))

    items = []
    for v in datos.get("vulnerabilities", []):
        cve = v.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        items.append(
            {
                "id": cve.get("id", "?"),
                "score": _score(cve),
                "severidad": _severidad(cve),
                "resumen": desc[:160],
            }
        )
    items.sort(key=lambda x: x["score"], reverse=True)
    return items[:limite]


def analizar(producto: str | None, version: str | None) -> list[Finding]:
    if not producto or not version:
        return [
            Finding(
                "CVE",
                "Sin versión de servidor para correlacionar CVEs",
                Risk.INFO,
                "No se detectó producto+versión exactos; no se consultó el NVD.",
            )
        ]

    log.info("  Consultando NVD para %s %s...", producto, version)
    cves = consultar_nvd(producto, version)
    if not cves:
        return [
            Finding(
                "CVE",
                f"Sin CVEs correlacionados para {producto} {version}",
                Risk.INFO,
                "El NVD no devolvió resultados (o no hubo respuesta). Verifique manualmente.",
                referencia="https://nvd.nist.gov",
            )
        ]

    findings: list[Finding] = []
    for c in cves:
        nivel = _SEVERIDAD.get(c["severidad"], Risk.MEDIO)
        log.info("  [!] %s (%s, CVSS %.1f)", c["id"], c["severidad"], c["score"])
        findings.append(
            Finding(
                "CVE",
                f"{c['id']} — {producto} {version} (CVSS {c['score']:.1f} {c['severidad']})",
                nivel,
                c["resumen"] or "Sin descripción.",
                referencia=f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                evidencia=f"keyword: {producto} {version}",
            )
        )
    return findings
