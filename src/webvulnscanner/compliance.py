"""Mapeo de hallazgos a controles de cumplimiento (PCI-DSS, ISO 27001, NIST 800-53).

Deriva los controles de la categoría OWASP 2025 de cada hallazgo, para que el
reporte sirva como evidencia de auditoría. Complementa el tagging OWASP.
"""

from __future__ import annotations

from collections import defaultdict

from webvulnscanner.models import Finding

# Categoría OWASP 2025 → controles por marco (representativos, no exhaustivos).
_CONTROLES: dict[str, dict[str, list[str]]] = {
    "A01:2025": {  # Broken Access Control (incl. SSRF)
        "PCI-DSS": ["7.1", "7.2"],
        "ISO 27001": ["A.5.15", "A.8.3"],
        "NIST 800-53": ["AC-3", "AC-6"],
    },
    "A02:2025": {  # Security Misconfiguration
        "PCI-DSS": ["2.2"],
        "ISO 27001": ["A.8.9"],
        "NIST 800-53": ["CM-6", "CM-7"],
    },
    "A03:2025": {  # Software Supply Chain Failures
        "PCI-DSS": ["6.3.2"],
        "ISO 27001": ["A.8.28", "A.5.23"],
        "NIST 800-53": ["SA-12", "SR-3"],
    },
    "A04:2025": {  # Cryptographic Failures
        "PCI-DSS": ["4.1", "3.4"],
        "ISO 27001": ["A.8.24"],
        "NIST 800-53": ["SC-8", "SC-13"],
    },
    "A05:2025": {  # Injection
        "PCI-DSS": ["6.2.4"],
        "ISO 27001": ["A.8.28"],
        "NIST 800-53": ["SI-10"],
    },
    "A06:2025": {  # Insecure Design
        "PCI-DSS": ["6.2"],
        "ISO 27001": ["A.8.25"],
        "NIST 800-53": ["SA-8"],
    },
    "A07:2025": {  # Authentication Failures
        "PCI-DSS": ["8.3"],
        "ISO 27001": ["A.5.17", "A.8.5"],
        "NIST 800-53": ["IA-2", "IA-5"],
    },
    "A08:2025": {  # Software or Data Integrity Failures
        "PCI-DSS": ["6.4.3", "11.5"],
        "ISO 27001": ["A.8.28"],
        "NIST 800-53": ["SI-7"],
    },
    "A09:2025": {  # Logging & Alerting Failures
        "PCI-DSS": ["10.2"],
        "ISO 27001": ["A.8.15"],
        "NIST 800-53": ["AU-2", "AU-6"],
    },
    "A10:2025": {  # Mishandling of Exceptional Conditions
        "PCI-DSS": ["6.2.4"],
        "ISO 27001": ["A.8.26"],
        "NIST 800-53": ["SI-11"],
    },
}


def controles_de(f: Finding) -> dict[str, list[str]]:
    """Controles aplicables a un hallazgo según su categoría OWASP. {} si no mapea."""
    if not f.owasp:
        return {}
    return _CONTROLES.get(f.owasp, {})


def resumen(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Agrupa: {marco: {control: nº de hallazgos que lo incumplen}}."""
    res: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        for marco, controles in controles_de(f).items():
            for c in controles:
                res[marco][c] += 1
    return {marco: dict(ctrl) for marco, ctrl in res.items()}
