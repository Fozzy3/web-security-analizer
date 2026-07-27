"""Detección de librerías JavaScript vulnerables (estilo retire.js, nativo).

Extrae librería+versión de las URLs de <script> descubiertas por el crawler y
las compara contra una base curada de versiones mínimas seguras. Es un subconjunto
demostrativo; para cobertura total, el wrapper de `retire` (externo) la completa.
"""

from __future__ import annotations

import logging
import re

from webvulnscanner.models import Finding, Risk

log = logging.getLogger("webvulnscanner.retirejs")

# librería -> (regex que captura la versión en la URL, versión mínima segura, motivo)
_DB = {
    "jquery": (r"jquery[.-]?(\d+\.\d+\.\d+)", (3, 5, 0), "XSS en versiones < 3.5 (CVE-2020-11022/11023)"),
    "angular": (r"angular[.-]?(\d+\.\d+\.\d+)", (1, 8, 0), "Múltiples XSS/DoS en AngularJS < 1.8"),
    "bootstrap": (r"bootstrap[.-]?(\d+\.\d+\.\d+)", (4, 3, 1), "XSS en data-attributes < 4.3.1"),
    "lodash": (r"lodash[.-]?(\d+\.\d+\.\d+)", (4, 17, 21), "Prototype pollution < 4.17.21"),
    "moment": (r"moment[.-]?(\d+\.\d+\.\d+)", (2, 29, 4), "ReDoS/path traversal < 2.29.4"),
    "handlebars": (r"handlebars[.-]?(\d+\.\d+\.\d+)", (4, 7, 7), "Prototype pollution < 4.7.7"),
}


def _vtupla(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def analizar_scripts(scripts: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for url in scripts:
        low = url.lower()
        for lib, (patron, minimo, motivo) in _DB.items():
            m = re.search(patron, low)
            if not m:
                continue
            version = m.group(1)
            if _vtupla(version) < minimo:
                minstr = ".".join(map(str, minimo))
                log.info("  [!] %s %s vulnerable (< %s)", lib, version, minstr)
                findings.append(
                    Finding(
                        "JS vulnerable",
                        f"{lib} {version} desactualizado (seguro >= {minstr})",
                        Risk.MEDIO,
                        f"{motivo}. Actualice a {minstr} o superior.",
                        referencia=url,
                        evidencia=f"{lib} {version}",
                        owasp="A06:2021",
                    )
                )
            break
    return findings
