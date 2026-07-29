# csrf-detection Specification

## Purpose

Detectar formularios que realizan acciones con efecto (POST) sin token anti-CSRF ni protección SameSite. Usa los forms que el crawler ya descubre. Pasivo sobre el HTML servido (no envía payloads), disponible sin `--authorized`.

## Requirements

### Requirement: Formulario sin token anti-CSRF

El sistema SHOULD marcar formularios con `method=post` que carezcan de un campo con nombre de token conocido (`csrf`, `_token`, `authenticity_token`, `__requestverificationtoken`, `xsrf`) y cuyo sitio no fije `SameSite` en cookies.

#### Scenario: POST sin token
- GIVEN un `<form method=post>` sin input de token conocido
- AND las cookies no declaran SameSite
- WHEN corre el módulo
- THEN se reporta posible CSRF MEDIO con la acción del form

#### Scenario: form con token no se marca
- GIVEN un form POST con `<input name="_token">`
- WHEN corre el módulo
- THEN no se reporta hallazgo para ese form

#### Scenario: SameSite mitiga
- GIVEN un form POST sin token
- AND una cookie con `SameSite=Lax`
- WHEN corre el módulo
- THEN el hallazgo baja a BAJO (mitigación parcial)
