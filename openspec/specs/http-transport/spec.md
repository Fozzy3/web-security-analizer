# http-transport Specification

## Purpose

Extender la única frontera de red (`net.py`) para soportar métodos HTTP con cuerpo, cortesía (throttle) y passthrough de sesión, sin romper `fetch()` existente. Base fundacional de toda la capa activa.

## Requirements

### Requirement: Request con método y cuerpo

El sistema MUST ofrecer `request(dominio, ruta, *, method, data, json, headers)` que soporte GET/POST/PUT/DELETE/PATCH y envíe cuerpo form-urlencoded o JSON. `fetch()` MUST seguir funcionando idéntico (delegando en `request` con method=GET).

#### Scenario: POST con cuerpo form
- GIVEN un endpoint que refleja el body
- WHEN se llama `request(d, "/x", method="POST", data={"a":"1"})`
- THEN la petición usa POST con `Content-Type: application/x-www-form-urlencoded`
- AND el body contiene `a=1`

#### Scenario: JSON body
- GIVEN `json={"a":1}`
- WHEN se llama request
- THEN `Content-Type: application/json` y el body es JSON válido

#### Scenario: fetch sin cambios
- GIVEN el mismo objetivo
- WHEN se llama `fetch(d, "/")`
- THEN el comportamiento es idéntico al actual (GET, HTTPS→HTTP fallback)

### Requirement: Passthrough de sesión

El sistema MUST permitir inyectar credenciales de sesión (cookie, header arbitrario, bearer token) que se adjuntan a TODAS las peticiones del escaneo. El sistema MUST NOT registrar los valores de autenticación en logs.

#### Scenario: cookie de sesión
- GIVEN `--cookie "sid=abc"`
- WHEN corre cualquier módulo que hace request
- THEN toda petición incluye `Cookie: sid=abc`

#### Scenario: no fuga en log
- GIVEN un bearer token configurado
- WHEN se emite log de progreso
- THEN el valor del token no aparece en la salida de log

### Requirement: Throttle de cortesía

El sistema SHOULD limitar la tasa de peticiones por objetivo según `--delay` (segundos entre peticiones) o `--rps`. Por defecto sin throttle (compat).

#### Scenario: delay aplicado
- GIVEN `--delay 0.5`
- WHEN se hacen 3 peticiones secuenciales
- THEN transcurren >= 1.0s en total
