# jwt-analysis Specification

## Purpose

Analizar debilidades en JSON Web Tokens que aparecen en contenido servido al cliente o en cookies/headers. Complementa `secrets` (que solo detecta presencia). Pasivo: decodifica el JWT, no lo falsifica.

## Requirements

### Requirement: Debilidades estructurales de JWT

El sistema SHOULD decodificar el header y payload de cada JWT hallado y reportar: algoritmo `none` (ALTO), algoritmo HS256 con secreto trivial verificable contra una lista corta (ALTO), ausencia de `exp` (MEDIO), y `exp` ya vencido en tokens activos (BAJO).

#### Scenario: alg none
- GIVEN un JWT con header `{"alg":"none"}`
- WHEN corre el módulo
- THEN se reporta ALTO "JWT acepta alg:none"

#### Scenario: secreto débil HS256
- GIVEN un JWT HS256 firmado con `secret`
- WHEN se verifica contra la lista de secretos triviales
- THEN se reporta ALTO con el secreto encontrado (redactado parcialmente)

#### Scenario: sin exp
- GIVEN un JWT sin claim `exp`
- WHEN corre el módulo
- THEN se reporta MEDIO "JWT sin expiración"

#### Scenario: JWT válido y fuerte
- GIVEN un JWT RS256 con exp futuro
- WHEN corre el módulo
- THEN no se reporta debilidad (solo INFO opcional)
