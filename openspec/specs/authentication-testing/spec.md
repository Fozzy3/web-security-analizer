# authentication-testing Specification

## Purpose

Detectar fallos de autenticación (A07:2025, API2): enumeración de usuarios, credenciales por defecto, ausencia de rate-limit en login y session fixation. Activo, gateado tras `autorizado=True`.

## Requirements

### Requirement: Enumeración de usuarios

El sistema SHOULD comparar respuestas del login/recuperación ante usuario existente vs. inexistente (mensaje, código, tiempo) y reportar si el sistema revela la existencia de cuentas.

#### Scenario: mensajes diferenciados
- GIVEN un formulario de login detectado
- WHEN se prueba un usuario probable vs. uno aleatorio
- THEN si el mensaje/código difiere de forma consistente, se reporta enumeración de usuarios MEDIO

### Requirement: Credenciales por defecto

El sistema SHOULD, sobre un panel de login identificado por fingerprint, probar el conjunto de credenciales por defecto conocidas del producto detectado (p.ej. admin/admin, admin/password y las propias de la tecnología). Reporta si alguna autentica.

#### Scenario: default creds válidas
- GIVEN un panel de una tecnología con credenciales por defecto conocidas
- WHEN se prueba el set de credenciales del producto
- THEN si alguna autentica, se reporta credenciales por defecto ALTO (A07:2025) con la combinación hallada

#### Scenario: ninguna default cred funciona
- GIVEN un panel sin credenciales por defecto activas
- WHEN se prueba el set
- THEN no se reporta hallazgo

### Requirement: Ausencia de rate-limit en login

El sistema SHOULD emitir una serie de intentos fallidos suficiente para determinar si hay throttling y reportar si ninguno es rechazado. MUST respetar `Sesion.delay` para no saturar.

#### Scenario: sin throttling
- GIVEN una serie de intentos fallidos consecutivos
- WHEN ninguno recibe 429 ni retardo creciente
- THEN se reporta ausencia de rate-limit en autenticación MEDIO

### Requirement: Session fixation

El sistema SHOULD verificar si el identificador de sesión cambia tras autenticarse.

#### Scenario: id de sesión no rota
- GIVEN una cookie de sesión pre-login
- WHEN se autentica y la cookie no cambia
- THEN se reporta posible session fixation MEDIO
