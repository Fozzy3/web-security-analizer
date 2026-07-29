# access-control-testing Specification

## Purpose

Detectar fallos de control de acceso — el riesgo #1 (A01:2025, API1/API3/API5) — mediante IDOR/BOLA (manipulación de identificadores de objeto) y forced browsing. El alcance **automatizado es de solo lectura** (GET) más forced browsing sin sesión; requiere sesión (Fase L) y va gateado tras `autorizado=True`. El **write-IDOR (métodos mutantes POST/PUT/PATCH/DELETE) se difiere a verificación manual** (ver `tasks.md` 5.4): en caja negra no hay prueba automatizada de autorización de escritura que sea a la vez fiable y garantizada no destructiva, por lo que se documenta como control manual en vez de automatizarlo.

## Requirements

### Requirement: IDOR / BOLA por manipulación de object-ID

El sistema SHOULD, sobre parámetros o segmentos de ruta que parezcan identificadores (numéricos o secuenciales), probar valores vecinos (±1, otro id) con la sesión activa mediante **GET (lectura)**. Reporta acceso no autorizado cuando un objeto ajeno responde de forma que evidencia acceso (2xx con contenido ajeno). El write-IDOR (métodos mutantes) queda **fuera del alcance automatizado** y se cubre por verificación manual.

#### Scenario: read-IDOR
- GIVEN una URL autenticada `/api/user/1001` que responde datos del usuario
- WHEN se solicita `/api/user/1002` con la misma sesión
- THEN si responde 2xx con datos de otro usuario, se reporta IDOR de lectura ALTO (A01:2025)

#### Scenario: write-IDOR (diferido a verificación manual)
- GIVEN un endpoint mutante `PUT /api/user/1001/profile`
- WHEN corre el módulo automatizado
- THEN NO se emite ninguna petición mutante ni finding automático — la escritura se documenta como control manual (no destructivo) en el reporte, no se automatiza

#### Scenario: acceso correctamente denegado
- GIVEN el objeto ajeno responde 403/404 con la sesión
- WHEN corre la prueba
- THEN no se reporta hallazgo

### Requirement: Forced browsing autenticado

El sistema SHOULD solicitar rutas administrativas/privadas conocidas con y sin sesión y reportar cuando una ruta sensible es accesible sin autorización o expone función administrativa.

#### Scenario: panel admin sin control
- GIVEN `/admin/users` responde 200 sin sesión
- WHEN corre el módulo
- THEN se reporta control de acceso roto ALTO (A01:2025)
