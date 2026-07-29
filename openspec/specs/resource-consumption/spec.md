# resource-consumption Specification

## Purpose

Cubrir API4:2023 Unrestricted Resource Consumption verificando si el objetivo aplica rate-limiting. Activo, gateado tras `autorizado=True`. Emite una ráfaga suficiente para determinar la presencia o ausencia de control; el volumen es configurable (`--rl-burst`) y respeta `Sesion.delay`.

## Requirements

### Requirement: Detección de rate-limiting

El sistema SHOULD emitir una ráfaga de peticiones (configurable vía `--rl-burst`, con un valor por defecto razonable) a un endpoint y reportar si ninguna es limitada (sin `429`, sin `Retry-After`, sin caída de tasa). MUST respetar `Sesion.delay`.

#### Scenario: sin límite observado
- GIVEN un endpoint que responde a la ráfaga completa
- WHEN ninguna devuelve 429 ni cabeceras de rate-limit
- THEN se reporta ausencia de rate-limiting BAJO (API4:2023)

#### Scenario: rate-limit presente
- GIVEN el endpoint devuelve 429 o `X-RateLimit-Remaining`
- WHEN corre la prueba
- THEN no se reporta hallazgo (o INFO: rate-limiting presente)
