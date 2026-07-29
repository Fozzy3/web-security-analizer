# ssrf-header-injection Specification

## Purpose

Detección activa de SSRF (A01:2025/API7), Host Header Injection y cache poisoning básico. Complementa el indicio pasivo de `cloud-misconfig`. Gateado tras `autorizado=True`. Payloads no destructivos; SSRF se confirma por respuesta observable, sin depender de infraestructura externa del atacante.

## Requirements

### Requirement: SSRF activo sobre parámetros tipo URL

El sistema SHOULD inyectar en parámetros que aceptan URLs (los `_PARAMS_REDIRECT` y descubiertos) destinos internos observables (`http://169.254.169.254/`, `http://localhost/`) y reportar SSRF cuando la respuesta refleja contenido del recurso interno o cambia de forma que evidencia la petición server-side.

#### Scenario: metadata reflejada
- GIVEN un parámetro que la app usa para fetch server-side
- WHEN se inyecta `http://169.254.169.254/latest/meta-data/`
- THEN si la respuesta contiene datos de metadata, se reporta SSRF ALTO (A01:2025)

#### Scenario: sin SSRF
- GIVEN el parámetro no dispara petición server-side
- WHEN corre la prueba
- THEN no se reporta hallazgo

### Requirement: Host Header Injection

El sistema SHOULD enviar un `Host` (y `X-Forwarded-Host`) atacante y reportar si el valor se refleja en la respuesta (enlaces absolutos, redirects) — vector de password-reset poisoning.

#### Scenario: host reflejado
- GIVEN una petición con `Host: evil.example`
- WHEN la respuesta o un redirect contiene `evil.example`
- THEN se reporta Host Header Injection MEDIO

### Requirement: Cache poisoning básico

El sistema SHOULD detectar reflejo de headers no cacheables (`X-Forwarded-Host`, `X-Forwarded-Scheme`) junto a headers de caché que sugieran envenenamiento.

#### Scenario: reflejo cacheable
- GIVEN un `X-Forwarded-Host` reflejado en respuesta con `Cache-Control: public`
- WHEN corre la prueba
- THEN se reporta indicio de cache poisoning MEDIO
