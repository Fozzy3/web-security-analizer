# finding-classification Specification

## Purpose

Enriquecer cada hallazgo con CWE (clase de debilidad) y un vector/score CVSS v3.1 nativo, para priorización objetiva más allá del nivel de riesgo cualitativo. Se computa localmente, sin dependencias ni red.

## Requirements

### Requirement: Campos CWE y CVSS en el modelo

El sistema MUST extender `Finding` con campos opcionales `cwe` (p.ej. "CWE-79") y `cvss` (dict con `vector` y `score`). MUST serializar/deserializar en to_dict/from_dict manteniendo compatibilidad con reportes previos (campos ausentes → None).

#### Scenario: retrocompatibilidad de deserialización
- GIVEN un reporte .json anterior sin cwe/cvss
- WHEN se carga con `Finding.from_dict`
- THEN cwe y cvss son None y no falla

### Requirement: Asignación de CWE/CVSS por tipo de hallazgo

El sistema SHOULD asignar CWE y un CVSS base según el tipo de hallazgo (mapa por módulo/hallazgo), calculando el score desde el vector.

#### Scenario: XSS reflejado clasificado
- GIVEN un hallazgo de XSS reflejado
- WHEN corre la clasificación
- THEN se asigna CWE-79 y un vector CVSS con score coherente (>= 6.1)

#### Scenario: score derivado del vector
- GIVEN un vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- WHEN se computa el score
- THEN el score redondea a 7.5 según la fórmula oficial CVSS v3.1
