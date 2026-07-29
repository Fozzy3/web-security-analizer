"""Export a SARIF 2.1.0 — el formato estándar que GitHub/Azure/GitLab entienden
para mostrar hallazgos de seguridad en el pipeline (pestaña Security).
"""

from __future__ import annotations

import json

from webvulnscanner import __version__
from webvulnscanner.models import Finding, Risk, ScanResult

_NIVEL_SARIF = {
    Risk.ALTO: "error",
    Risk.MEDIO: "warning",
    Risk.BAJO: "note",
    Risk.INFO: "note",
    Risk.OK: "none",
}


def _rule_id(f: Finding) -> str:
    return f.modulo.lower().replace("/", "-").replace(" ", "-")


def render(result: ScanResult) -> str:
    # OK/none no aporta como "resultado"; se omiten.
    findings = [f for f in result.findings if f.riesgo != Risk.OK]

    reglas: dict[str, dict] = {}
    resultados = []
    for f in findings:
        rid = _rule_id(f)
        reglas.setdefault(rid, {"id": rid, "name": f.modulo, "shortDescription": {"text": f.modulo}})
        resultados.append(
            {
                "ruleId": rid,
                "level": _NIVEL_SARIF[f.riesgo],
                "message": {"text": f"{f.hallazgo} — {f.descripcion}"},
                "properties": {
                    "riesgo": f.riesgo.value,
                    "referencia": f.referencia,
                    "owasp": f.owasp,
                    "api": f.api,
                    "cwe": f.cwe,
                    "cvss": f.cvss["score"] if f.cvss else None,
                },
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.dominio}}}],
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WebVulnScanner",
                        "version": __version__,
                        "informationUri": "https://crt.sh",
                        "rules": list(reglas.values()),
                    }
                },
                "results": resultados,
            }
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
