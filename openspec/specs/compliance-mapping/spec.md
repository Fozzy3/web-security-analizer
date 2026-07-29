# compliance-mapping Specification

## Purpose

Mapear cada hallazgo a controles de marcos de cumplimiento (PCI-DSS, ISO 27001, NIST 800-53), para que el reporte sirva como evidencia de auditoría. Complementa el tagging OWASP existente. Local, sin red.

## Requirements

### Requirement: Etiquetado de compliance por hallazgo

El sistema SHOULD asignar a cada hallazgo los controles aplicables de PCI-DSS, ISO 27001 y NIST 800-53, derivados de su categoría OWASP/CWE.

#### Scenario: TLS obsoleto mapeado
- GIVEN un hallazgo de protocolo TLS obsoleto
- WHEN corre el mapeo
- THEN se etiqueta con PCI-DSS 4.1 (o equivalente), ISO 27001:2022 A.8.24 (Use of cryptography), y un control NIST SC-*

#### Scenario: hallazgo sin mapeo conocido
- GIVEN un hallazgo informativo sin control asociado
- WHEN corre el mapeo
- THEN no se le asignan controles y no falla

### Requirement: Resumen de cumplimiento en el reporte

El sistema SHOULD incluir en el reporte una sección que agrupe hallazgos por control incumplido, por marco.

#### Scenario: sección de compliance
- GIVEN un escaneo con hallazgos mapeados
- WHEN se genera el reporte
- THEN existe un resumen "Controles afectados" por marco con el conteo
