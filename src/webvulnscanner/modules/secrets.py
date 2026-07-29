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


# Booster opcional: detección por entropía (detect-secrets). Conservador para
# no ahogar en falsos positivos de JS minificado: umbral alto y cota de resultados.
_DS_PLUGINS: list | None
try:
    from detect_secrets.plugins.high_entropy_strings import (
        Base64HighEntropyString,
        HexHighEntropyString,
    )

    _DS_PLUGINS = [Base64HighEntropyString(limit=4.5), HexHighEntropyString(limit=3.0)]
except Exception:  # noqa: BLE001
    _DS_PLUGINS = None


# Solo se considera entropía en líneas que "huelen" a secreto asignado; y se
# excluyen hashes públicos (SRI) que también son de alta entropía pero no secretos.
_PALABRAS_SECRETO = ("key", "token", "secret", "passw", "pwd", "auth", "bearer", "credential", "apikey")
_EXCLUIR_ENTROPIA = ("integrity", "sha256-", "sha384-", "sha512-", "srcset", "data:image")


def _por_entropia(texto: str, *, max_hits: int = 5) -> list[tuple[str, Risk, str]]:
    if not _DS_PLUGINS:
        return []
    hallados: list[tuple[str, Risk, str]] = []
    vistos: set[str] = set()
    for linea in texto.splitlines():
        low = linea.lower()
        if any(x in low for x in _EXCLUIR_ENTROPIA) or not any(k in low for k in _PALABRAS_SECRETO):
            continue
        for plugin in _DS_PLUGINS:
            for h in plugin.analyze_line(filename="x", line=linea):
                v = h.secret_value or ""
                if len(v) >= 24 and v[:16] not in vistos:
                    vistos.add(v[:16])
                    hallados.append(("Cadena de alta entropía (posible secreto)", Risk.MEDIO, v[:12] + "…"))
                    if len(hallados) >= max_hits:
                        return hallados
    return hallados


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
    hallados.extend(_por_entropia(texto))
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
