# error-handling-audit Specification

## Purpose

Cubrir A10:2025 Mishandling of Exceptional Conditions (categoría nueva) provocando condiciones de error controladas y detectando fugas: stack traces, modo debug activo, mensajes verbosos que revelan rutas/tecnología/consultas. Activo suave (peticiones malformadas benignas), gateado tras `autorizado=True`.

## Requirements

### Requirement: Stack traces y errores verbosos

El sistema SHOULD enviar entradas que induzcan error (tipo inválido, valor fuera de rango, parámetro faltante, método inesperado) y reportar si la respuesta expone un stack trace o traza de framework.

#### Scenario: stack trace expuesto
- GIVEN un endpoint que recibe un tipo inválido
- WHEN la respuesta contiene una firma de stack trace (`Traceback`, `at java.`, `Exception in`, `stack trace`)
- THEN se reporta fuga por error MEDIO (A10:2025)

#### Scenario: error manejado limpiamente
- GIVEN el endpoint devuelve un 400/500 genérico sin detalle
- WHEN corre la prueba
- THEN no se reporta hallazgo

### Requirement: Modo debug activo

El sistema SHOULD detectar indicadores de modo debug en producción (p.ej. panel de debug de framework, `X-Debug`, consola interactiva de error).

#### Scenario: debug de framework
- GIVEN una respuesta de error con panel de debug interactivo (Werkzeug, Symfony, Rails)
- WHEN corre la prueba
- THEN se reporta modo debug en producción ALTO (A10:2025)
