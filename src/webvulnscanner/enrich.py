"""Enriquecimiento de hallazgos CVE con inteligencia de explotación.

- **EPSS** (FIRST): probabilidad de que un CVE sea explotado en los próximos 30 días.
- **CISA KEV**: catálogo de CVEs que se están explotando activamente en la realidad.

Un CVSS alto que además está en KEV o con EPSS elevado es prioridad real, no
teórica. Anota los findings de CVE in-place.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request

from webvulnscanner.cache import cached_json
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import USER_AGENT

log = logging.getLogger("webvulnscanner.enrich")

_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"


def _descargar(url: str, timeout: int) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        log.info("  [-] fuente no respondió (%s): %s", url.split("/")[2], e)
        return {}


def cves_kev(*, timeout: int = 20) -> set[str]:
    datos = cached_json("cisa-kev", 86_400, lambda: _descargar(_KEV_URL, timeout))
    if not isinstance(datos, dict):
        return set()
    return {v.get("cveID", "") for v in datos.get("vulnerabilities", [])}


def epss_scores(cve_ids: list[str], *, timeout: int = 20) -> dict[str, float]:
    if not cve_ids:
        return {}
    url = _EPSS_URL.format(cves=",".join(sorted(set(cve_ids))))
    # La clave debe ser estable entre procesos: hash() de str va sembrado al
    # azar (PYTHONHASHSEED), así que usarlo aquí anulaba la caché por completo.
    datos = cached_json(f"epss:{url}", 21_600, lambda: _descargar(url, timeout))
    if not isinstance(datos, dict):
        return {}
    return {d["cve"]: float(d.get("epss", 0.0)) for d in datos.get("data", [])}


def enriquecer(findings: list[Finding]) -> None:
    """Anota los findings de CVE con EPSS y KEV (in-place)."""
    ids: list[str] = []
    for f in findings:
        m = _RE_CVE.search(f.hallazgo)
        if m:
            ids.append(m.group(0))
    if not ids:
        return

    kev = cves_kev()
    epss = epss_scores(ids)

    for f in findings:
        m = _RE_CVE.search(f.hallazgo)
        if not m:
            continue
        cve = m.group(0)
        notas = []
        if cve in epss:
            notas.append(f"EPSS {epss[cve] * 100:.1f}%")
        if cve in kev:
            notas.append("⚠ EN CISA KEV (explotado activamente)")
            f.riesgo = Risk.ALTO  # explotación real → máxima prioridad
        if notas:
            f.descripcion = f"[{' · '.join(notas)}] " + f.descripcion
            log.info("  [i] %s: %s", cve, ", ".join(notas))
