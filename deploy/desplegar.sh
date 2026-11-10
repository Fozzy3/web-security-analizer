#!/usr/bin/env bash
# Sube Web Security Analyzer al server compartido y lo (re)levanta.
# Convención de server-edge: código en /opt/wsa, Traefik lo publica por labels.
#
#   bash deploy/desplegar.sh          (VPS=otro-alias para cambiar el host ssh)
#
# La imagen (con los motores externos: nuclei, subfinder, testssl, sslyze, wpscan…)
# se arma ACÁ y se sube por ssh: el build es pesado y no conviene en el server
# compartido de 2 núcleos. La primera vez crea /opt/wsa/.env y se detiene.
set -euo pipefail
cd "$(dirname "$0")/.."
VPS=${VPS:-edge}
IMG=webvulnscanner:2.0

# 1. Build local (--pull para refrescar las últimas versiones de nuclei/subfinder)
docker build -t "$IMG" .

# 2. Código (para /opt/wsa: compose, .env, informes). Sin la imagen: esa va por ssh.
rsync -az --delete --exclude .git --exclude .venv --exclude venv --exclude __pycache__ \
  --exclude .pytest_cache --exclude .ruff_cache --exclude .mypy_cache --exclude .impeccable \
  --exclude docs --exclude openspec --exclude informes --exclude 'reporte_*' --exclude .env \
  ./ "$VPS":/opt/wsa/

# 3. Imagen recién construida → al server (gzip -1: rápido, la imagen es grande)
docker save "$IMG" | gzip -1 | ssh "$VPS" 'gunzip | docker load'

# 4. Levantar (sin --build: usa la imagen que acabamos de cargar)
ssh "$VPS" bash -s <<'EOF'
set -euo pipefail
cd /opt/wsa
if [ ! -f .env ]; then
  cp deploy/env.example .env
  echo "Creado /opt/wsa/.env: completá DEMO_AUTH y volvé a correr." >&2
  exit 1
fi
docker compose --project-directory . -f deploy/docker-compose.prod.yml up -d
docker compose --project-directory . -f deploy/docker-compose.prod.yml ps
EOF
