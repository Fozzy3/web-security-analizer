# cloud-misconfig Specification

## Purpose

Detectar malas configuraciones de almacenamiento cloud y exposición de endpoints de metadata referenciados desde el sitio. Pasivo: lee recursos ya enlazados y prueba acceso público de lectura a buckets referenciados.

## Requirements

### Requirement: Almacenamiento cloud público

El sistema SHOULD extraer URLs de buckets (S3 `*.s3*.amazonaws.com`, GCS `storage.googleapis.com`, Azure `*.blob.core.windows.net`) referenciadas en el HTML/JS y verificar si el listado del bucket es públicamente accesible.

#### Scenario: bucket S3 listable
- GIVEN una URL de bucket S3 referenciada
- WHEN una petición al bucket raíz devuelve un `ListBucketResult` XML
- THEN se reporta ALTO "bucket S3 público listable" con el nombre

#### Scenario: bucket privado
- GIVEN un bucket referenciado que devuelve AccessDenied
- WHEN corre el módulo
- THEN no se reporta (o INFO de bucket referenciado)

### Requirement: Referencia a metadata cloud

El sistema SHOULD marcar referencias en el frontend a endpoints de metadata (`169.254.169.254`, `metadata.google.internal`) como indicio de posible SSRF.

#### Scenario: metadata endpoint en JS
- GIVEN un script referencia `169.254.169.254`
- WHEN corre el módulo
- THEN se reporta MEDIO indicio de SSRF hacia metadata
