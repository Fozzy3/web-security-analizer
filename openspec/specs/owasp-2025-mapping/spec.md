# owasp-2025-mapping Specification

## Purpose

Migrar el etiquetado OWASP de `owasp.py` del Top 10 2021 al **2025**, que reorganizó las categorías: SSRF (era A10:2021) se fusionó en A01 Broken Access Control, y aparecieron A03 Software Supply Chain Failures y A10 Mishandling of Exceptional Conditions. Mantener reportes vigentes y trazables.

## Requirements

### Requirement: Catálogo de categorías 2025

El sistema MUST exponer las 10 categorías del OWASP Top 10 2025 con sus códigos `A01:2025`…`A10:2025` y nombres oficiales.

#### Scenario: catálogo actualizado
- GIVEN el módulo owasp
- WHEN se consulta el catálogo
- THEN contiene A03:2025 "Software Supply Chain Failures" y A10:2025 "Mishandling of Exceptional Conditions"
- AND NO contiene la antigua "A10:2021 Server-Side Request Forgery"

### Requirement: Remapeo de hallazgos existentes

El sistema MUST reasignar los hallazgos que antes iban a A10:2021 (SSRF) a `A01:2025`, y clasificar supply-chain (retire.js, CVE, fingerprint con versión, SBOM) bajo `A03:2025`.

#### Scenario: SSRF ahora es A01
- GIVEN un hallazgo de indicio SSRF (metadata endpoint)
- WHEN corre el etiquetado
- THEN su categoría es "A01:2025"

#### Scenario: componente vulnerable es A03
- GIVEN un hallazgo de librería JS obsoleta (retire.js)
- WHEN corre el etiquetado
- THEN su categoría es "A03:2025"

### Requirement: Errores excepcionales bajo A10

El sistema SHOULD asignar los hallazgos de fugas por error/stack trace/debug a `A10:2025`.

#### Scenario: stack trace es A10
- GIVEN un hallazgo de stack trace expuesto
- WHEN corre el etiquetado
- THEN su categoría es "A10:2025"
