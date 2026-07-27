"""Módulo 7: Exposición de archivos y rutas sensibles.

Solicita rutas conocidas (sin fuzzing ni diccionarios agresivos) para detectar
fugas: repositorios .git expuestos, archivos .env, backups, robots.txt con
rutas jugosas y ausencia de security.txt. Solo peticiones GET normales.
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.disclosure")

# ruta -> (firma que confirma exposición real, nivel, hallazgo, descripción)
_RUTAS = {
    "/.git/HEAD": ("ref:", Risk.ALTO,
                   "Repositorio .git expuesto",
                   "El directorio .git es accesible: se puede reconstruir el código fuente y su historial."),
    "/.env": ("=", Risk.ALTO,
              "Archivo .env expuesto",
              "Archivo de entorno accesible: suele contener credenciales, claves y secretos."),
    "/config.php.bak": ("<?php", Risk.ALTO,
                        "Backup de configuración expuesto",
                        "Archivo de respaldo con código/credenciales accesible públicamente."),
    "/.well-known/security.txt": ("contact", Risk.OK,
                                  "security.txt presente",
                                  "Publica un canal de divulgación de vulnerabilidades (buena práctica, RFC 9116)."),
}


def _confirma(body: str, firma: str) -> bool:
    return firma.lower() in (body or "").lower()


def analizar(dominio: str) -> list[Finding]:
    findings: list[Finding] = []

    for ruta, (firma, nivel, titulo, desc) in _RUTAS.items():
        resp = fetch(dominio, ruta, max_body=8000)
        if resp and resp.status == 200 and _confirma(resp.body, firma):
            log.info("  [!] %s (%s)", titulo, ruta)
            findings.append(Finding("Exposición", titulo, nivel, desc,
                                    referencia=f"{resp.esquema}://{dominio}{ruta}",
                                    evidencia=resp.body[:120]))
        elif nivel == Risk.OK:
            # Reportar ausencia solo para security.txt (recomendación, no fuga)
            findings.append(Finding("Exposición", "security.txt ausente", Risk.BAJO,
                                    "No publica /.well-known/security.txt (RFC 9116) para reportar vulnerabilidades."))

    # robots.txt: informativo + señalar rutas 'Disallow' potencialmente sensibles
    robots = fetch(dominio, "/robots.txt", max_body=8000)
    if robots and robots.status == 200 and "user-agent" in robots.body.lower():
        disallow = [l.split(":", 1)[1].strip() for l in robots.body.splitlines()
                    if l.lower().startswith("disallow") and ":" in l]
        disallow = [d for d in disallow if d and d != "/"]
        log.info("  [+] robots.txt con %d rutas Disallow", len(disallow))
        if disallow:
            findings.append(Finding("Exposición", f"robots.txt revela {len(disallow)} rutas ocultas",
                                    Risk.INFO,
                                    "Las rutas en 'Disallow' orientan al atacante hacia zonas 'privadas': "
                                    + ", ".join(disallow[:10]),
                                    referencia=f"{robots.esquema}://{dominio}/robots.txt",
                                    evidencia="\n".join(disallow[:20])))

    return findings
