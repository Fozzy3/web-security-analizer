"""Fase T: SBOM (CycloneDX) y dependency confusion (A03:2025 Supply Chain).

Consolida los componentes ya detectados (fingerprint, retire.js, CVE) en un SBOM
CycloneDX 1.5 y señala paquetes con scope interno (`@empresa/...`) como riesgo de
dependency confusion. Pasivo: no descubre nada nuevo, solo consolida.
"""

from __future__ import annotations

import logging
import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.sbom")

_MODULOS_COMP = {"Fingerprint", "JS vulnerable", "CVE", "Shodan"}
# "nombre 1.2.3" evitando IPs (lookahead: la versión no va seguida de otro .dígito).
_RE_COMP = re.compile(r"([A-Za-z][\w.\-]{1,30}?)[\s:/_-]+v?(\d+\.\d+(?:\.\d+)?)(?!\.\d)")
# Paquetes con scope (npm): candidatos a dependency confusion si el scope es interno.
_RE_SCOPED = re.compile(r"@[\w.\-]+/[\w.\-]+")
# Identificadores CVE presentes en cualquier campo del hallazgo (retire.js, NVD, wpscan).
_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def generar(componentes: list[dict]) -> dict:
    """Documento CycloneDX 1.5 a partir de una lista de {name, version[, cves]}.

    Cada componente recibe un `bom-ref` estable para poder referenciarlo. Cuando
    un componente trae CVEs conocidos se emite además un array top-level
    `vulnerabilities` (CycloneDX 1.5) que los referencia por `affects.ref`. Un
    SBOM sin CVEs conocidos omite `vulnerabilities` y sigue siendo válido.
    """
    components: list[dict] = []
    vulnerabilities: list[dict] = []
    for i, c in enumerate(componentes):
        ref = f"comp-{i}"
        components.append(
            {"type": "library", "bom-ref": ref, "name": c["name"], "version": c.get("version", "")}
        )
        for cid in c.get("cves", []):
            vulnerabilities.append(
                {
                    "id": cid,
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cid}"},
                    "affects": [{"ref": ref}],
                }
            )
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities
    return doc


def componentes_de(findings: list[Finding]) -> list[dict]:
    """Extrae {name, version, cves} de los hallazgos de componentes (deduplicado).

    Los CVEs de todos los campos del hallazgo (hallazgo/descripción/evidencia/
    referencia) se acumulan sobre el componente correlacionado por name+version,
    de modo que un mismo paquete detectado por fingerprint y CVE se consolida.
    """
    comps: list[dict] = []
    por_clave: dict[tuple[str, str], dict] = {}
    for f in findings:
        if f.modulo not in _MODULOS_COMP:
            continue
        m = _RE_COMP.search(f"{f.hallazgo} {f.evidencia or ''}")
        if not m:
            continue
        nombre, version = m.group(1).strip(" :-"), m.group(2)
        clave = (nombre.lower(), version)
        comp = por_clave.get(clave)
        if comp is None:
            comp = {"name": nombre, "version": version, "cves": []}
            por_clave[clave] = comp
            comps.append(comp)
        campos = " ".join(x for x in (f.hallazgo, f.descripcion, f.evidencia, f.referencia) if x)
        for cid in _RE_CVE.findall(campos):
            if cid not in comp["cves"]:
                comp["cves"].append(cid)
    return comps


def _paquetes_internos(texto: str) -> set[str]:
    return set(_RE_SCOPED.findall(texto or ""))


def analizar(dominio: str, scripts: set[str], *, max_scripts: int = 15) -> list[Finding]:
    """Reporta paquetes con scope referenciados (indicio de dependency confusion)."""
    textos: list[str] = []
    home = fetch(dominio, "/")
    if home:
        textos.append(home.body)
    for url in list(scripts)[:max_scripts]:
        ruta = url.split(dominio, 1)[-1] if dominio in url else url
        r = fetch(dominio, ruta, max_body=400_000)
        if r:
            textos.append(r.body)

    paquetes: set[str] = set()
    for t in textos:
        paquetes |= _paquetes_internos(t)

    findings: list[Finding] = []
    for pkg in sorted(paquetes):
        log.info("  [i] Paquete con scope referenciado: %s", pkg)
        findings.append(
            Finding(
                "Supply Chain",
                f"Posible dependency confusion: paquete con scope '{pkg}'",
                Risk.BAJO,
                "Se referencia un paquete con scope que podría ser interno. Si el scope no está "
                "reservado en el registro público, un atacante puede publicar uno malicioso. "
                "Reserve el scope y fije el registro.",
                evidencia=pkg,
                owasp="A03:2025",
            )
        )
    return findings
