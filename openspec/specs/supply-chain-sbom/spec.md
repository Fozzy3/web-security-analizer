# supply-chain-sbom Specification

## Purpose

Cubrir A03:2025 Software Supply Chain Failures (categoría nueva del Top 10 2025) generando un SBOM (Software Bill of Materials) en formato CycloneDX a partir de los componentes ya detectados (retire.js, fingerprint) y señalando riesgo de dependency confusion. Pasivo: solo consolida lo ya descubierto. Nativo, sin dependencias.

## Requirements

### Requirement: SBOM CycloneDX

El sistema SHOULD emitir, opcionalmente (`--sbom PATH`), un documento CycloneDX 1.5 con los componentes JS/tecnologías detectados (nombre, versión cuando exista, tipo library) y sus CVEs conocidos.

#### Scenario: SBOM válido
- GIVEN un escaneo que detectó jQuery 1.8 y un servidor Apache 2.4.29
- WHEN se corre con `--sbom sbom.json`
- THEN el archivo es CycloneDX 1.5 válido con esos componentes y su versión

#### Scenario: sin componentes
- GIVEN un escaneo sin tecnologías versionadas
- WHEN se corre con `--sbom`
- THEN se emite un SBOM válido con lista de componentes vacía

### Requirement: Indicio de dependency confusion

El sistema SHOULD marcar paquetes referenciados que parezcan internos (scoped `@empresa/…`, nombres no publicados en registros públicos) como riesgo de dependency confusion.

#### Scenario: paquete interno referenciado
- GIVEN el frontend referencia `@corp/internal-utils`
- WHEN corre el módulo
- THEN se reporta indicio de dependency confusion BAJO (A03:2025)
