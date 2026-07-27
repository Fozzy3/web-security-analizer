"""Escaneo de secretos expuestos en HTML/JS (nativo, regex).

Busca claves de API, tokens y material criptográfico que no debería estar en el
frontend. Pasivo: solo lee recursos ya servidos.
"""

from __future__ import annotations

import logging
import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.secrets")

# nombre -> (regex, nivel). Patrones específicos para minimizar falsos positivos.
_PATRONES = {
    "AWS Access Key": (re.compile(r"AKIA[0-9A-Z]{16}"), Risk.ALTO),
    "Google API Key": (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Risk.ALTO),
    "Slack Token": (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), Risk.ALTO),
    "Stripe Secret Key": (re.compile(r"sk_live_[0-9A-Za-z]{24,}"), Risk.ALTO),
    "GitHub Token": (re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), Risk.ALTO),
    "Private Key": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Risk.ALTO),
    "JWT": (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), Risk.MEDIO),
    "Clave genérica asignada": (
        re.compile(r"""(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["'][^"'\s]{8,}["']"""),
        Risk.MEDIO,
    ),
}


def escanear_texto(texto: str) -> list[tuple[str, Risk, str]]:
    """Devuelve (tipo, nivel, muestra) por cada secreto encontrado (deduplicado)."""
    vistos: set[str] = set()
    hallados: list[tuple[str, Risk, str]] = []
    for tipo, (rx, nivel) in _PATRONES.items():
        for m in rx.findall(texto):
            frag = m if isinstance(m, str) else m[0]
            clave = f"{tipo}:{frag[:16]}"
            if clave in vistos:
                continue
            vistos.add(clave)
            hallados.append((tipo, nivel, frag[:12] + "…"))
    return hallados


def analizar(dominio: str, scripts: set[str], *, max_scripts: int = 15) -> list[Finding]:
    findings: list[Finding] = []
    recursos: list[tuple[str, str]] = []

    home = fetch(dominio, "/")
    if home:
        recursos.append(("/", home.body))
    for url in list(scripts)[:max_scripts]:
        ruta = url.split(dominio, 1)[-1] if dominio in url else url
        resp = fetch(dominio, ruta, max_body=400_000)
        if resp:
            recursos.append((ruta, resp.body))

    for ruta, contenido in recursos:
        for tipo, nivel, muestra in escanear_texto(contenido):
            log.info("  [!] Secreto expuesto (%s) en %s", tipo, ruta)
            findings.append(
                Finding(
                    "Secretos",
                    f"Posible {tipo} expuesto en {ruta}",
                    nivel,
                    "Se detectó lo que parece un secreto en contenido servido al cliente. "
                    "Verifique y rote la credencial si es real; nunca incruste secretos en el frontend.",
                    evidencia=f"{tipo}: {muestra}",
                    owasp="A02:2021",
                )
            )
    return findings
