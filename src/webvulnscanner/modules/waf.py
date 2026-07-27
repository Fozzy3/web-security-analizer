"""Módulo 8: Detección de WAF / CDN.

Identifica cortafuegos de aplicación y CDNs por firmas en cabeceras y cookies.
Saberlo cambia la interpretación del resto (una IP de Cloudflare no es el
origen real).
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.waf")

# nombre -> lista de (header, subcadena esperada en su valor; "" = solo presencia)
_FIRMAS = {
    "Cloudflare": [("server", "cloudflare"), ("cf-ray", "")],
    "AWS CloudFront": [("via", "cloudfront"), ("x-amz-cf-id", "")],
    "Akamai": [("server", "akamaighost"), ("x-akamai-transformed", "")],
    "Sucuri": [("server", "sucuri"), ("x-sucuri-id", "")],
    "Imperva/Incapsula": [("x-iinfo", ""), ("x-cdn", "incapsula")],
    "Fastly": [("x-served-by", "cache"), ("x-fastly-request-id", "")],
    "Vercel": [("server", "vercel"), ("x-vercel-id", "")],
}


def detectar(headers: dict[str, str]) -> list[str]:
    detectados: list[str] = []
    for nombre, firmas in _FIRMAS.items():
        for header, sub in firmas:
            valor = headers.get(header)
            if valor is not None and (sub == "" or sub in valor.lower()):
                detectados.append(nombre)
                break
    return detectados


def analizar(respuesta: HttpResponse | None) -> list[Finding]:
    if respuesta is None:
        return []
    detectados = detectar(respuesta.headers)
    if not detectados:
        log.info("  [+] No se detectó WAF/CDN conocido")
        return [Finding("WAF/CDN", "No se detectó WAF/CDN conocido", Risk.INFO,
                        "No hay firmas de WAF/CDN comunes. El origen puede estar directamente expuesto.")]
    log.info("  [+] WAF/CDN: %s", ", ".join(detectados))
    return [Finding("WAF/CDN", f"Protegido por: {', '.join(detectados)}", Risk.INFO,
                    "Hay un WAF/CDN delante del origen. Las IPs observadas son del proveedor, "
                    "no necesariamente del servidor real.",
                    evidencia=", ".join(detectados))]
