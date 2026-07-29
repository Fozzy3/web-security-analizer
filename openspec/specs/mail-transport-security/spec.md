# mail-transport-security Specification

## Purpose

Complementar el módulo DNS de correo (SPF/DMARC/DKIM/BIMI) con MTA-STS y TLS-RPT, que fuerzan y monitorean TLS en el transporte de correo. Pasivo: consultas DNS + un GET al policy endpoint de MTA-STS.

## Requirements

### Requirement: Política MTA-STS

El sistema SHOULD consultar el registro `_mta-sts.<dominio>` (TXT) y, si existe, recuperar `https://mta-sts.<dominio>/.well-known/mta-sts.txt` para validar el modo (`enforce`/`testing`/`none`).

#### Scenario: MTA-STS en enforce
- GIVEN existe el TXT `_mta-sts` y la policy con `mode: enforce`
- WHEN corre el módulo
- THEN se reporta OK "MTA-STS en enforce"

#### Scenario: MTA-STS ausente
- GIVEN no existe el registro `_mta-sts`
- WHEN corre el módulo
- THEN se reporta BAJO "sin MTA-STS: downgrade de TLS en correo posible"

#### Scenario: policy en testing
- GIVEN policy con `mode: testing`
- WHEN corre el módulo
- THEN se reporta INFO "MTA-STS en testing (no fuerza TLS aún)"

### Requirement: Reporte TLS-RPT

El sistema SHOULD consultar `_smtp._tls.<dominio>` (TXT) y reportar si el dominio recibe reportes de fallos de TLS en correo.

#### Scenario: sin TLS-RPT
- GIVEN no existe `_smtp._tls`
- WHEN corre el módulo
- THEN se reporta INFO "sin TLS-RPT: no hay visibilidad de fallos TLS de correo"
