"""Módulo 4: Encabezados HTTP de seguridad.

No se limita a presencia/ausencia: parsea el *valor* de CSP y HSTS para
detectar configuraciones débiles (unsafe-inline, wildcards, max-age bajo).
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.headers")

# Headers cuya ausencia se reporta, con nivel y explicación.
_AUSENCIA = {
    "strict-transport-security": (
        Risk.MEDIO,
        "HSTS ausente: el navegador puede ser degradado a HTTP (SSL stripping).",
    ),
    "content-security-policy": (
        Risk.ALTO,
        "CSP ausente: sin defensa declarativa contra XSS. Es de los headers más importantes.",
    ),
    "x-frame-options": (
        Risk.MEDIO,
        "X-Frame-Options ausente: el sitio puede embeberse en iframes (clickjacking).",
    ),
    "x-content-type-options": (
        Risk.BAJO,
        "X-Content-Type-Options ausente: el navegador puede hacer MIME sniffing.",
    ),
    "referrer-policy": (Risk.BAJO, "Referrer-Policy ausente: puede filtrar URLs a terceros."),
    "permissions-policy": (
        Risk.BAJO,
        "Permissions-Policy ausente: scripts de terceros podrían usar cámara/micrófono/GPS.",
    ),
}


def evaluar_csp(valor: str) -> list[tuple[Risk, str]]:
    """Analiza una Content-Security-Policy y devuelve (nivel, problema)."""
    v = valor.lower()
    problemas: list[tuple[Risk, str]] = []
    if "unsafe-inline" in v:
        problemas.append(
            (
                Risk.ALTO,
                "CSP contiene 'unsafe-inline': permite scripts/estilos inline, anulando gran parte de la protección XSS.",
            )
        )
    if "unsafe-eval" in v:
        problemas.append(
            (Risk.MEDIO, "CSP contiene 'unsafe-eval': permite eval(), ampliando la superficie XSS.")
        )
    # Wildcard en directivas de script/objeto/default
    for directiva in ("default-src", "script-src", "object-src"):
        if f"{directiva} *" in v or f"{directiva} 'self' *" in v:
            problemas.append(
                (
                    Risk.ALTO,
                    f"CSP usa comodín '*' en {directiva}: permite cargar recursos de cualquier origen.",
                )
            )
    if "default-src" not in v and "script-src" not in v:
        problemas.append((Risk.MEDIO, "CSP sin default-src ni script-src: cobertura incompleta."))
    return problemas


def evaluar_hsts(valor: str) -> list[tuple[Risk, str]]:
    """Analiza Strict-Transport-Security."""
    v = valor.lower()
    problemas: list[tuple[Risk, str]] = []
    max_age = 0
    for parte in v.split(";"):
        parte = parte.strip()
        if parte.startswith("max-age"):
            try:
                max_age = int(parte.split("=", 1)[1])
            except (ValueError, IndexError):
                max_age = 0
    if max_age == 0:
        problemas.append((Risk.MEDIO, "HSTS con max-age=0 o inválido: efectivamente desactivado."))
    elif max_age < 15_552_000:  # 180 días
        problemas.append((Risk.BAJO, f"HSTS con max-age={max_age}s (< 6 meses). Se recomienda >= 15552000."))
    if "includesubdomains" not in v:
        problemas.append((Risk.BAJO, "HSTS sin 'includeSubDomains': los subdominios no quedan protegidos."))
    return problemas


def analizar(respuesta: HttpResponse | None) -> list[Finding]:
    findings: list[Finding] = []
    if respuesta is None:
        return [
            Finding(
                "Headers HTTP",
                "No se pudieron obtener los encabezados HTTP",
                Risk.INFO,
                "El servidor no respondió por HTTP ni HTTPS.",
            )
        ]

    h = respuesta.headers
    log.info("  Analizando headers (%s)...", respuesta.esquema.upper())

    # CSP — presencia + calidad
    csp = h.get("content-security-policy")
    if csp:
        problemas = evaluar_csp(csp)
        if problemas:
            for nivel, msg in problemas:
                log.info("  [!] %s", msg)
                findings.append(Finding("Headers HTTP", msg.split(":")[0], nivel, msg, evidencia=csp[:200]))
        else:
            findings.append(
                Finding(
                    "Headers HTTP",
                    "CSP presente y sin patrones inseguros",
                    Risk.OK,
                    "Content-Security-Policy configurada correctamente.",
                    evidencia=csp[:200],
                )
            )
    else:
        nivel, desc = _AUSENCIA["content-security-policy"]
        log.info("  [x] CSP ausente [%s]", nivel.value.upper())
        findings.append(Finding("Headers HTTP", "Content-Security-Policy ausente", nivel, desc))

    # HSTS — presencia + calidad
    hsts = h.get("strict-transport-security")
    if hsts:
        problemas = evaluar_hsts(hsts)
        if problemas:
            for nivel, msg in problemas:
                log.info("  [!] %s", msg)
                findings.append(Finding("Headers HTTP", msg.split(":")[0], nivel, msg, evidencia=hsts))
        else:
            findings.append(
                Finding(
                    "Headers HTTP",
                    "HSTS presente y robusto",
                    Risk.OK,
                    "Strict-Transport-Security bien configurado.",
                    evidencia=hsts,
                )
            )
    else:
        nivel, desc = _AUSENCIA["strict-transport-security"]
        findings.append(Finding("Headers HTTP", "Strict-Transport-Security ausente", nivel, desc))

    # Resto: presencia/ausencia simple
    for header, (nivel, desc) in _AUSENCIA.items():
        if header in ("content-security-policy", "strict-transport-security"):
            continue
        valor = h.get(header)
        titulo = header.title().replace("Http", "HTTP")
        if valor:
            findings.append(
                Finding(
                    "Headers HTTP",
                    f"{titulo} presente",
                    Risk.OK,
                    f"{titulo} configurado.",
                    evidencia=valor[:120],
                )
            )
        else:
            log.info("  [x] %s ausente [%s]", header, nivel.value.upper())
            findings.append(Finding("Headers HTTP", f"{titulo} ausente", nivel, desc))

    return findings
