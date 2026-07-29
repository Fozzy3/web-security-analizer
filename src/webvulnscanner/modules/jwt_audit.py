"""Análisis de debilidades en JSON Web Tokens servidos al cliente.

Complementa `secrets` (que solo detecta presencia). Pasivo: decodifica el token
y verifica debilidades — NO lo falsifica ni lo usa. Detecta `alg:none`, secretos
HS256 triviales, ausencia de `exp` y tokens vencidos.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import time

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.jwt")

# JWT en contenido servido: la firma puede ir vacía (alg:none).
_RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Secretos HS256 comunes: verificar contra esta lista NO es fuerza bruta real,
# es comprobar que el firmante no usó un secreto de diccionario.
_SECRETOS_DEBILES = (
    "secret",
    "secretkey",
    "password",
    "changeme",
    "admin",
    "jwt",
    "key",
    "private",
    "token",
    "123456",
    "test",
    "your-256-bit-secret",
    "your_jwt_secret",
    "supersecret",
    "s3cr3t",
    "qwerty",
)


def _decodificar(parte: str) -> dict:
    pad = "=" * (-len(parte) % 4)
    return json.loads(base64.urlsafe_b64decode(parte + pad).decode("utf-8", "replace"))


def _secreto_debil(partes: list[str]) -> str | None:
    """Devuelve el secreto trivial que verifica la firma HS256, o None."""
    mensaje = f"{partes[0]}.{partes[1]}".encode()
    for s in _SECRETOS_DEBILES:
        calc = (
            base64.urlsafe_b64encode(hmac.new(s.encode(), mensaje, hashlib.sha256).digest())
            .rstrip(b"=")
            .decode()
        )
        if hmac.compare_digest(calc, partes[2]):
            return s
    return None


def analizar_token(token: str) -> list[Finding]:
    """Evalúa un JWT y devuelve sus debilidades. Núcleo puro (sin red)."""
    partes = token.split(".")
    if len(partes) != 3:
        return []
    try:
        header = _decodificar(partes[0])
        payload = _decodificar(partes[1])
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append(
            Finding(
                "JWT",
                "JWT acepta alg:none (sin firma)",
                Risk.ALTO,
                "El token usa 'alg: none': cualquiera puede forjar un token válido. "
                "Rechace 'none' y fije el algoritmo esperado en el servidor.",
                owasp="A07:2021",
            )
        )
    elif alg == "hs256":
        secreto = _secreto_debil(partes)
        if secreto:
            findings.append(
                Finding(
                    "JWT",
                    "JWT HS256 firmado con secreto débil",
                    Risk.ALTO,
                    "La firma se verifica con un secreto de diccionario: se pueden forjar tokens. "
                    "Use un secreto largo y aleatorio.",
                    evidencia=f"secreto: {secreto}",
                    owasp="A07:2021",
                )
            )

    if "exp" not in payload:
        findings.append(
            Finding(
                "JWT",
                "JWT sin expiración (exp)",
                Risk.MEDIO,
                "El token no declara 'exp': si se filtra, es válido para siempre.",
                owasp="A07:2021",
            )
        )
    else:
        exp = payload["exp"]
        if isinstance(exp, int | float) and exp < time.time():
            findings.append(
                Finding(
                    "JWT",
                    "JWT vencido presente en contenido activo",
                    Risk.BAJO,
                    "Se sirve un token ya expirado; revise por qué sigue en el contenido.",
                    owasp="A07:2021",
                )
            )
    return findings


def analizar(dominio: str, scripts: set[str], *, max_scripts: int = 15) -> list[Finding]:
    """Cosecha JWTs del HTML y los scripts, y evalúa cada uno (deduplicado)."""
    textos: list[str] = []
    home = fetch(dominio, "/")
    if home:
        textos.append(home.body)
    for url in list(scripts)[:max_scripts]:
        ruta = url.split(dominio, 1)[-1] if dominio in url else url
        r = fetch(dominio, ruta, max_body=400_000)
        if r:
            textos.append(r.body)

    vistos: set[str] = set()
    findings: list[Finding] = []
    for texto in textos:
        for token in _RE_JWT.findall(texto):
            if token in vistos:
                continue
            vistos.add(token)
            findings.extend(analizar_token(token))
    return findings
