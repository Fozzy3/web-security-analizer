# active-injection-depth Specification

## Purpose

Profundizar el testing activo de inyección: cubrir formularios/POST (no solo query), por-parámetro (no cortar al primer hallazgo), y clases nuevas. Gateado tras `autorizado=True`, payloads no destructivos.

## Requirements

### Requirement: Inyección en formularios y POST

El sistema MUST probar los formularios descubiertos por el crawler (`crawl.forms`), enviando payloads por el método real del form (GET o POST) sobre cada `input`. MUST reutilizar `net.request`.

#### Scenario: XSS reflejado vía POST
- GIVEN un form POST cuyo input se refleja sin codificar
- WHEN se envía el marcador `wvs9z7xq"<x>` por POST
- THEN se reporta XSS reflejado ALTO con el parámetro y método

#### Scenario: form GET también cubierto
- GIVEN un form con method=get
- WHEN se prueba
- THEN el payload va en query-string

### Requirement: Cobertura por-parámetro

El sistema SHOULD probar todos los parámetros descubiertos (con una cota de seguridad), no detenerse en el primer hallazgo, deduplicando por (ruta, parámetro, clase).

#### Scenario: dos params vulnerables
- GIVEN dos parámetros reflejan el payload
- WHEN corre la inyección
- THEN se reportan ambos, no solo el primero

### Requirement: SQLi ciega basada en tiempo

El sistema SHOULD detectar SQLi blind comparando latencia base vs. payload de retardo (`SLEEP`/`pg_sleep`), con umbral y una segunda confirmación para evitar falsos por jitter.

#### Scenario: retardo confirmado
- GIVEN un endpoint cuyo tiempo sube con el payload de sleep
- WHEN se mide base y payload dos veces
- THEN se reporta SQLi blind ALTO solo si el retardo es consistente

### Requirement: Clases de inyección adicionales

El sistema SHOULD probar path-traversal/LFI, SSTI y CRLF con firmas de confirmación no destructivas. Command injection se limita a marcadores de eco sin efectos secundarios.

#### Scenario: LFI confirmado por firma
- GIVEN `?file=../../../../etc/passwd`
- WHEN la respuesta contiene `root:.*:0:0:`
- THEN se reporta path traversal ALTO

#### Scenario: SSTI confirmado por evaluación
- GIVEN payload `${7*7}` / `{{7*7}}`
- WHEN la respuesta contiene `49`
- THEN se reporta SSTI ALTO
