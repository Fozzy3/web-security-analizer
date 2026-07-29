"""Fase S: SSRF activo + Host Header Injection + cache poisoning (A01:2025/API7).

Activo, gateado tras `autorizado=True`. Complementa el indicio pasivo de `cloud`.
SSRF se confirma por respuesta observable (contenido de metadata interna); no
depende de infraestructura externa del atacante.
"""

from __future__ import annotations

import logging
import urllib.parse

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import request

log = logging.getLogger("webvulnscanner.ssrf")

# Parámetros que suelen aceptar URLs (candidatos a SSRF).
_PARAMS_SSRF = (
    "url",
    "uri",
    "dest",
    "destination",
    "redirect",
    "next",
    "callback",
    "feed",
    "host",
    "target",
    "file",
    "path",
    "proxy",
    "load",
    "fetch",
    "src",
)
_PAYLOADS = (
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
)
# Firmas de que la respuesta trae contenido de metadata de la instancia.
_FIRMAS_META = ("meta-data", "ami-id", "instance-id", "iam/security-credentials", "instance-action")
_HOST_MARCADOR = "wvs-ssrf.evil.example"


def _confirma_ssrf(body: str) -> bool:
    b = (body or "").lower()
    return any(s in b for s in _FIRMAS_META)


def _probar_ssrf(dominio: str, crawl: Crawl | None) -> list[Finding]:
    params = set(_PARAMS_SSRF)
    if crawl:
        for nombres in crawl.params.values():
            params |= {p for p in nombres if p.lower() in _PARAMS_SSRF}
    for param in sorted(params):
        for payload in _PAYLOADS:
            r = request(dominio, f"/?{param}={urllib.parse.quote(payload)}")
            if r and _confirma_ssrf(r.body):
                log.info("  [!!] Posible SSRF vía parámetro '%s'", param)
                return [
                    Finding(
                        "SSRF",
                        f"Posible SSRF vía parámetro '{param}'",
                        Risk.ALTO,
                        "El servidor recupera una URL controlada y devuelve contenido interno "
                        "(metadata de la instancia). Valide y restrinja los destinos server-side.",
                        referencia=f"/?{param}=",
                        evidencia=payload,
                        owasp="A01:2025",
                    )
                ]
    return []


def _probar_host_header(dominio: str) -> list[Finding]:
    r = request(dominio, "/", headers={"Host": _HOST_MARCADOR, "X-Forwarded-Host": _HOST_MARCADOR})
    if r is None:
        return []
    reflejado = _HOST_MARCADOR in r.body or _HOST_MARCADOR in (r.header("location") or "")
    if not reflejado:
        return []
    findings = [
        Finding(
            "SSRF",
            "Host Header Injection (Host/X-Forwarded-Host reflejado)",
            Risk.MEDIO,
            "El servidor refleja un Host atacante en la respuesta/redirect: habilita "
            "password-reset poisoning y envenenamiento de enlaces. Fije el host canónico.",
            evidencia=_HOST_MARCADOR,
            owasp="A01:2025",
        )
    ]
    if "public" in (r.header("cache-control") or "").lower():
        log.info("  [!!] Indicio de cache poisoning: host reflejado y respuesta cacheable")
        findings.append(
            Finding(
                "SSRF",
                "Indicio de cache poisoning (host reflejado y respuesta cacheable)",
                Risk.MEDIO,
                "El host inyectado se refleja y la respuesta es cacheable (Cache-Control public): "
                "un atacante podría envenenar la caché. Excluya headers no confiables de la clave de caché.",
                owasp="A02:2025",
            )
        )
    return findings


def analizar(dominio: str, crawl: Crawl | None = None) -> list[Finding]:
    return _probar_ssrf(dominio, crawl) + _probar_host_header(dominio)
