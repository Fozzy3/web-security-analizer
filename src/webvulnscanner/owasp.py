"""Etiquetado de hallazgos con la categoría OWASP Top 10 (2021).

Permite estructurar el reporte por categoría OWASP, como esperan las auditorías.
El mapeo es por módulo (suficiente para la mayoría); casos como CVE/fingerprint
con versión caen en A06 aunque su módulo sea otro.
"""

from __future__ import annotations

from webvulnscanner.models import Finding

CATEGORIAS = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

# Módulo -> categoría OWASP por defecto.
_POR_MODULO = {
    "Reconocimiento": "A05:2021",
    "Escaneo de Puertos": "A05:2021",
    "TLS/HTTPS": "A02:2021",
    "Headers HTTP": "A05:2021",
    "DNS": "A05:2021",
    "Subdominios": "A05:2021",
    "Exposición": "A05:2021",
    "WAF/CDN": "A05:2021",
    "Fingerprint": "A06:2021",
    "CVE": "A06:2021",
    "Shodan": "A06:2021",
    "Cookies": "A05:2021",
    "CORS": "A05:2021",
    "Inyección": "A03:2021",
    "Fuzzing": "A05:2021",
    "JS vulnerable": "A06:2021",
    "Secretos": "A02:2021",
    "SSRF": "A10:2021",
    "Open Redirect": "A01:2021",
    "Integridad": "A08:2021",
}


def categoria(f: Finding) -> str | None:
    """Devuelve la categoría OWASP (id) para un hallazgo, o None."""
    # Overrides por contenido: un takeover es control de acceso; secreto = cripto.
    if "takeover" in f.hallazgo.lower():
        return "A01:2021"
    return _POR_MODULO.get(f.modulo)


def etiquetar(findings: list[Finding]) -> None:
    """Rellena in-place el campo `owasp` de cada hallazgo que no lo tenga."""
    for f in findings:
        if f.owasp is None:
            f.owasp = categoria(f)
