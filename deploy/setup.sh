#!/usr/bin/env bash
# Despliegue todo-en-uno: Greenbone (OpenVAS) + WebVulnScanner web.
#
# 1. Baja el compose oficial de Greenbone Community (fuente de verdad; no lo
#    reproducimos a mano para que no se desactualice).
# 2. Levanta la pila Greenbone + este servicio web, compartiendo el socket GMP.
# 3. Crea el usuario admin de GVM con la contraseña de $GVM_PASSWORD.
#
# Requisitos: Docker + docker compose v2, ~4 GB RAM libres, ~10 GB disco.
# La PRIMERA vez, Greenbone sincroniza el feed de NVTs: tarda HORAS y el módulo
# OpenVAS no dará resultados hasta que termine (el resto del escáner sí).
set -euo pipefail
cd "$(dirname "$0")"

GREENBONE_URL="https://greenbone.github.io/docs/latest/_static/docker-compose-22.4.yml"
GREENBONE_FILE="greenbone.yml"
: "${GVM_PASSWORD:=admin}"
export GVM_PASSWORD

if [ ! -f "$GREENBONE_FILE" ]; then
  echo "▶ Bajando compose oficial de Greenbone…"
  if ! curl -fsSL "$GREENBONE_URL" -o "$GREENBONE_FILE"; then
    cat <<EOF
✗ No se pudo bajar el compose de Greenbone desde:
    $GREENBONE_URL
  (la URL cambia entre versiones). Descargá el vigente desde
  https://greenbone.github.io/docs/latest/22.4/container/  y guardalo como:
    deploy/$GREENBONE_FILE
  Luego volvé a correr este script.
EOF
    exit 1
  fi
fi

echo "▶ Levantando Greenbone + WebVulnScanner (build incluido)…"
docker compose -f "$GREENBONE_FILE" -f docker-compose.yml up -d --build

echo "▶ Creando usuario admin de GVM (idempotente)…"
docker compose -f "$GREENBONE_FILE" -f docker-compose.yml exec -u gvmd gvmd \
  gvmd --create-user=admin --password="$GVM_PASSWORD" 2>/dev/null \
  || docker compose -f "$GREENBONE_FILE" -f docker-compose.yml exec -u gvmd gvmd \
     gvmd --user=admin --new-password="$GVM_PASSWORD"

cat <<EOF

✅ Listo. Web en:  http://localhost:8000
   Pegá una URL y arranca.

⏳ La primera vez, el feed de NVTs tarda HORAS en sincronizar. Hasta entonces el
   módulo OpenVAS se marca "en progreso"/sin resultados; el resto del escáner
   funciona igual. Seguí el avance con:
     docker compose -f $GREENBONE_FILE -f docker-compose.yml logs -f gvmd

⚠ Cambiá GVM_PASSWORD y no expongas :8000 a internet sin auth (corre escaneos
   activos contra el objetivo que se pegue).
EOF
