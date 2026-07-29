# api-surface-discovery Specification

## Purpose

Descubrir superficie de API moderna: documentación OpenAPI/Swagger expuesta y endpoints GraphQL con introspección habilitada. Pasivo (GET a rutas conocidas + una consulta GraphQL estándar de introspección, que es una lectura, no un ataque).

## Requirements

### Requirement: Documentación OpenAPI/Swagger expuesta

El sistema SHOULD solicitar rutas conocidas (`/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui.html`, `/v3/api-docs`) y reportar cuando devuelven un documento OpenAPI/Swagger válido.

#### Scenario: openapi.json expuesto
- GIVEN `/openapi.json` responde 200 con `{"openapi":"3..."}`
- WHEN corre el módulo
- THEN se reporta superficie de API expuesta INFO/BAJO con la cantidad de endpoints documentados

#### Scenario: ruta ausente
- GIVEN todas las rutas devuelven 404
- WHEN corre el módulo
- THEN no se reporta hallazgo

### Requirement: GraphQL introspection habilitada

El sistema SHOULD enviar la query de introspección estándar a endpoints GraphQL comunes (`/graphql`, `/api/graphql`) y reportar si el esquema es introspectable en producción.

#### Scenario: introspección abierta
- GIVEN `/graphql` responde el `__schema` completo
- WHEN corre el módulo
- THEN se reporta introspección habilitada MEDIO con el número de tipos

#### Scenario: introspección deshabilitada
- GIVEN `/graphql` rechaza la introspección
- WHEN corre el módulo
- THEN no se reporta hallazgo de introspección
