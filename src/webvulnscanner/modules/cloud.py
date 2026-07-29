"""Misconfiguración de almacenamiento cloud y exposición de metadata.

Pasivo: lee el HTML/JS servido, extrae URLs de buckets referenciados y comprueba
si su listado es público; además marca referencias a endpoints de metadata
(169.254.169.254, metadata.google.internal) como indicio de SSRF.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse, fetch

log = logging.getLogger("webvulnscanner.cloud")

# Buckets de S3 / GCS / Azure referenciados en el contenido.
_RE_BUCKET = re.compile(
    r"https?://[\w.\-]*(?:s3[\w.\-]*\.amazonaws\.com|storage\.googleapis\.com|[\w\-]+\.blob\.core\.windows\.net)",
    re.I,
)
_METADATA = ("169.254.169.254", "metadata.google.internal")


def _buckets(texto: str) -> set[str]:
    return {m.rstrip("/") for m in _RE_BUCKET.findall(texto or "")}


def _refs_metadata(texto: str) -> bool:
    t = (texto or "").lower()
    return any(m in t for m in _METADATA)


def fetch_url(url: str) -> HttpResponse | None:
    """GET a una URL completa (host externo, p.ej. un bucket)."""
    p = urlparse(url)
    return fetch(p.netloc, p.path or "/")


def analizar(dominio: str, scripts: set[str], *, max_scripts: int = 15) -> list[Finding]:
    textos: list[str] = []
    home = fetch(dominio, "/")
    if home:
        textos.append(home.body)
    for url in list(scripts)[:max_scripts]:
        ruta = url.split(dominio, 1)[-1] if dominio in url else url
        r = fetch(dominio, ruta, max_body=400_000)
        if r:
            textos.append(r.body)

    contenido = "\n".join(textos)
    findings: list[Finding] = []

    buckets: set[str] = set()
    for t in textos:
        buckets |= _buckets(t)
    for base in sorted(buckets)[:20]:
        r = fetch_url(base)
        if r and "ListBucketResult" in r.body:
            log.info("  [!] Bucket público listable: %s", base)
            findings.append(
                Finding(
                    "Cloud",
                    f"Bucket de almacenamiento público listable: {base}",
                    Risk.ALTO,
                    "El bucket permite listar su contenido públicamente: posible fuga de datos. "
                    "Restrinja los permisos de listado.",
                    referencia=base,
                    owasp="A05:2021",
                )
            )

    if _refs_metadata(contenido):
        log.info("  [!] Referencia a endpoint de metadata cloud")
        findings.append(
            Finding(
                "Cloud",
                "Referencia a endpoint de metadata cloud en el frontend",
                Risk.MEDIO,
                "El contenido referencia un endpoint de metadata (169.254.169.254). Es un indicio "
                "de posible SSRF hacia metadata de la instancia; verifique el manejo server-side.",
                owasp="A10:2021",
            )
        )
    return findings
