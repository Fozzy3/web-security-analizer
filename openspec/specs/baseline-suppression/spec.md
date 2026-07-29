# baseline-suppression Specification

## Purpose

Permitir suprimir hallazgos ya revisados/aceptados mediante un archivo de baseline, para que escaneos repetidos en CI solo muestren lo nuevo. Imprescindible para uso en pipelines sin ruido.

## Requirements

### Requirement: Archivo de baseline

El sistema SHOULD leer un archivo de baseline (`--baseline PATH`, por defecto `.wvsignore` si existe) con huellas de hallazgos a suprimir. La huella MUST ser estable: hash de (modulo, hallazgo, ruta/referencia) — no del texto de descripción que puede variar.

#### Scenario: hallazgo suprimido
- GIVEN un baseline con la huella de un hallazgo
- WHEN ese hallazgo reaparece en el escaneo
- THEN se excluye del reporte y del conteo de riesgo

#### Scenario: hallazgo nuevo pasa
- GIVEN un baseline sin la huella de un hallazgo nuevo
- WHEN corre el escaneo
- THEN el hallazgo nuevo se reporta normalmente

### Requirement: Generación de baseline

El sistema SHOULD ofrecer `--write-baseline PATH` que escribe las huellas del escaneo actual como baseline aceptado.

#### Scenario: escribir baseline
- GIVEN un escaneo con N hallazgos
- WHEN se corre con `--write-baseline .wvsignore`
- THEN el archivo contiene N huellas y el siguiente escaneo idéntico reporta 0
