"""Descubrimiento de superficie de API: OpenAPI/Swagger y GraphQL introspection.

Pasivo: GET a rutas conocidas de documentación y una consulta de introspección
GraphQL estándar (una lectura, no un ataque). Una API cuya documentación o
esquema es público facilita el mapeo de la superficie de ataque.
"""

from __future__ import annotations

import json
import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch, request

log = logging.getLogger("webvulnscanner.api_discovery")

_OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
)
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/query")
_INTROSPECCION = {"query": "{__schema{types{name}}}"}


def _doc_openapi(body: str) -> dict | None:
    """Devuelve el documento si parece OpenAPI/Swagger, si no None."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    return doc if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) else None


def _analizar_openapi(dominio: str) -> list[Finding]:
    for ruta in _OPENAPI_PATHS:
        r = fetch(dominio, ruta)
        if not r or r.status != 200:
            continue
        doc = _doc_openapi(r.body)
        if doc is None:
            continue
        n = len(doc.get("paths", {})) if isinstance(doc.get("paths"), dict) else 0
        log.info("  [+] Documentación OpenAPI expuesta en %s (%d endpoints)", ruta, n)
        return [
            Finding(
                "API",
                f"Documentación OpenAPI/Swagger expuesta en {ruta}",
                Risk.BAJO,
                f"La especificación de la API es pública ({n} endpoints documentados): "
                "facilita el mapeo de la superficie de ataque. Restrinja el acceso en producción.",
                referencia=ruta,
                evidencia=f"{n} endpoints",
                owasp="A05:2021",
            )
        ]
    return []


def _analizar_graphql(dominio: str) -> list[Finding]:
    for ruta in _GRAPHQL_PATHS:
        r = request(dominio, ruta, method="POST", json=_INTROSPECCION)
        if not r or r.status != 200:
            continue
        if "__schema" not in r.body or "types" not in r.body:
            continue
        try:
            tipos = json.loads(r.body)["data"]["__schema"]["types"]
            n = len(tipos)
        except (json.JSONDecodeError, KeyError, TypeError):
            n = 0
        log.info("  [!] GraphQL introspection habilitada en %s (%d tipos)", ruta, n)
        return [
            Finding(
                "API",
                f"GraphQL introspection habilitada en {ruta}",
                Risk.MEDIO,
                f"El esquema GraphQL es introspectable ({n} tipos): expone toda la API. "
                "Deshabilite la introspección en producción.",
                referencia=ruta,
                evidencia=f"{n} tipos",
                owasp="A05:2021",
            )
        ]
    return []


def analizar(dominio: str) -> list[Finding]:
    return _analizar_openapi(dominio) + _analizar_graphql(dominio)
