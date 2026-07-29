"""Etiquetado de hallazgos con la categoría OWASP Top 10 **2025**.

Punto único de normalización: los módulos pueden emitir códigos 2021 (o ninguno);
`etiquetar` los normaliza todos a 2025. Cambios estructurales del 2025:
SSRF (era A10:2021) se fusionó en A01; Vulnerable Components (A06:2021) pasó a
A03 Software Supply Chain Failures; aparecieron A03 (nueva) y A10 (Mishandling of
Exceptional Conditions).
"""

from __future__ import annotations

from webvulnscanner.models import Finding

CATEGORIAS = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Remapeo 2021 → 2025 (para normalizar los códigos que aún emiten los módulos).
_REMAP = {
    "A01:2021": "A01:2025",  # Broken Access Control
    "A02:2021": "A04:2025",  # Cryptographic Failures
    "A03:2021": "A05:2025",  # Injection
    "A04:2021": "A06:2025",  # Insecure Design
    "A05:2021": "A02:2025",  # Security Misconfiguration
    "A06:2021": "A03:2025",  # Vulnerable Components → Supply Chain
    "A07:2021": "A07:2025",  # Authentication Failures
    "A08:2021": "A08:2025",  # Data Integrity Failures
    "A09:2021": "A09:2025",  # Logging Failures
    "A10:2021": "A01:2025",  # SSRF → Broken Access Control (fusionado)
}

# Módulo → categoría OWASP 2025 por defecto.
_POR_MODULO = {
    "Reconocimiento": "A02:2025",
    "Escaneo de Puertos": "A02:2025",
    "TLS/HTTPS": "A04:2025",
    "Headers HTTP": "A02:2025",
    "DNS": "A02:2025",
    "Subdominios": "A02:2025",
    "Exposición": "A02:2025",
    "WAF/CDN": "A02:2025",
    "Fingerprint": "A03:2025",
    "Stack": "A03:2025",
    "CVE": "A03:2025",
    "Shodan": "A03:2025",
    "Cookies": "A02:2025",
    "CORS": "A02:2025",
    "Inyección": "A05:2025",
    "Fuzzing": "A02:2025",
    "JS vulnerable": "A03:2025",
    "Secretos": "A04:2025",
    "SSRF": "A01:2025",
    "Open Redirect": "A01:2025",
    "Integridad": "A08:2025",
    "CSRF": "A01:2025",
    "JWT": "A07:2025",
    "WordPress": "A05:2025",
    "Frameworks": "A02:2025",
    "API": "A02:2025",
    "API Fuzzing": "A08:2025",
    "Cloud": "A02:2025",
    "MTA-STS": "A04:2025",
    "TLS-RPT": "A04:2025",
}


# ── API Security Top 10 2023 (eje paralelo al Top 10 web) ────────────────────
CATEGORIAS_API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Módulo → categoría API 2023 (solo los módulos con superficie de API; el resto → None).
_API_POR_MODULO = {
    "Control de Acceso": "API1:2023",  # IDOR/BOLA
    "Autenticación": "API2:2023",
    "JWT": "API2:2023",
    "SSRF": "API7:2023",
    "Rate Limiting": "API4:2023",
    "Cloud": "API8:2023",
    "CORS": "API8:2023",
    "API": "API9:2023",  # descubrimiento/inventario de API
    "API Fuzzing": "API10:2023",
}


def categoria_api(f: Finding) -> str | None:
    """Categoría API Security Top 10 2023 (id) para un hallazgo, o None."""
    # Forced browsing / función admin accesible → autorización a nivel de función.
    if "forced browsing" in f.hallazgo.lower():
        return "API5:2023"
    return _API_POR_MODULO.get(f.modulo)


def categoria(f: Finding) -> str | None:
    """Categoría OWASP 2025 (id) para un hallazgo, o None."""
    # Overrides por contenido: un takeover es control de acceso.
    if "takeover" in f.hallazgo.lower():
        return "A01:2025"
    # Errores/stack traces expuestos → categoría nueva de excepciones.
    if "stack trace" in f.hallazgo.lower() or "modo debug" in f.hallazgo.lower():
        return "A10:2025"
    if f.owasp:
        # Normalizar un código previo (2021 → 2025) o dejarlo si ya es 2025.
        return _REMAP.get(f.owasp, f.owasp)
    return _POR_MODULO.get(f.modulo)


def etiquetar(findings: list[Finding]) -> None:
    """Normaliza in-place la categoría OWASP 2025 y la API Top 10 2023 de cada hallazgo."""
    for f in findings:
        f.owasp = categoria(f)
        f.api = categoria_api(f)
