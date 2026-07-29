"""Clasificación de hallazgos: CWE (clase de debilidad) + CVSS v3.1 base.

El score CVSS se computa de forma NATIVA (fórmula oficial v3.1), sin dependencias.
Da una priorización objetiva más allá del nivel cualitativo. Anota los findings
in-place, como enrich/owasp.

# ponytail: solo base score (sin temporal/environmental) — se añaden si importan.
"""

from __future__ import annotations

import math

from webvulnscanner.models import Finding

# Pesos oficiales CVSS v3.1.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_IMPACTO = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed


def _roundup(x: float) -> float:
    """Redondeo hacia arriba a 1 decimal, según la especificación CVSS v3.1."""
    entero = round(x * 100_000)
    if entero % 10_000 == 0:
        return entero / 100_000.0
    return (math.floor(entero / 10_000) + 1) / 10.0


def cvss_base(vector: str) -> float:
    """Calcula el CVSS v3.1 base score (0.0–10.0) desde un vector."""
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    cambia = m.get("S") == "C"

    iss = 1 - (1 - _IMPACTO[m["C"]]) * (1 - _IMPACTO[m["I"]]) * (1 - _IMPACTO[m["A"]])
    impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if cambia else 6.42 * iss
    if impacto <= 0:
        return 0.0

    pr = (_PR_C if cambia else _PR_U)[m["PR"]]
    explotabilidad = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    bruto = impacto + explotabilidad
    if cambia:
        bruto *= 1.08
    return _roundup(min(bruto, 10.0))


# Mapa (subcadena en modulo+hallazgo) → (CWE, vector CVSS v3.1). Orden: específico
# primero (p.ej. "sql injection ciega" antes que "sql injection").
_MAPA: tuple[tuple[str, str, str], ...] = (
    ("xss", "CWE-79", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("sql injection ciega", "CWE-89", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("sql injection", "CWE-89", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("path traversal", "CWE-22", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("ssti", "CWE-1336", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("command injection", "CWE-78", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("crlf", "CWE-93", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    ("open redirect", "CWE-601", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("csrf", "CWE-352", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    ("ssrf", "CWE-918", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"),
    ("bucket", "CWE-284", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("metadata cloud", "CWE-918", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"),
    ("alg:none", "CWE-347", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("jwt", "CWE-347", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("secreto", "CWE-798", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("secret", "CWE-798", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("takeover", "CWE-350", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    ("cookie", "CWE-614", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("cors", "CWE-942", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("content-security-policy", "CWE-693", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("strict-transport-security", "CWE-319", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("certificado", "CWE-295", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    ("protocolo obsoleto", "CWE-327", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("cipher débil", "CWE-327", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("librería", "CWE-1104", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    (".git", "CWE-527", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (".env", "CWE-200", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
)


def clasificar(findings: list[Finding]) -> None:
    """Asigna CWE + CVSS a cada hallazgo cuyo tipo esté mapeado (in-place)."""
    for f in findings:
        heno = f"{f.modulo} {f.hallazgo}".lower()
        for substr, cwe, vector in _MAPA:
            if substr in heno:
                f.cwe = cwe
                f.cvss = {"vector": vector, "score": cvss_base(vector)}
                break
