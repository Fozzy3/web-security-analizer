# Imagen de WebVulnScanner: sirve tanto el CLI como la API/web.
# Incluye los motores externos rápidos (<10 min por análisis). El único que queda
# afuera es OpenVAS/Greenbone (su feed tarda HORAS y vive en su propio contenedor).
FROM python:3.12-slim

WORKDIR /app

# Paquetes de sistema:
#   nmap                         -> módulo nmap --script vuln
#   bash openssl bind9-dnsutils  -> testssl.sh (script bash: usa openssl y dig)
#   bsdextrautils                -> hexdump, que testssl.sh necesita
#   curl unzip ca-certificates   -> bajar los binarios de nuclei y subfinder
#   git                          -> clonar testssl.sh
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap bash openssl bind9-dnsutils bsdextrautils curl unzip ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# nuclei y subfinder: binarios estáticos oficiales (evita instalar Go). Última versión.
RUN set -eux; \
    for repo in projectdiscovery/nuclei projectdiscovery/subfinder; do \
      url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
            | grep -o "https://[^\"]*_linux_amd64.zip" | head -1); \
      curl -fsSL "$url" -o /tmp/t.zip; \
      unzip -o /tmp/t.zip -d /usr/local/bin "$(basename "$repo")"; \
      rm /tmp/t.zip; \
    done; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder; \
    nuclei -version; subfinder -version

# Plantillas de nuclei precargadas en la imagen: así el primer escaneo no espera la descarga.
RUN nuclei -update-templates -silent || true

# testssl.sh: es un script bash; se clona y se enlaza al PATH con el nombre que espera el código.
RUN git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# wpscan (Ruby): solo aporta en sitios WordPress. Se compila con dependencias de build que
# luego se quitan. Best-effort: si el gem falla, la imagen igual queda lista sin wpscan.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ruby ruby-dev build-essential \
      libcurl4-openssl-dev libffi-dev zlib1g-dev patch; \
    (gem install wpscan --no-document && wpscan --version) || echo "wpscan omitido (fallo el gem)"; \
    apt-get purge -y ruby-dev build-essential libcurl4-openssl-dev libffi-dev zlib1g-dev patch; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# Instalar primero solo los metadatos para aprovechar la caché de capas.
COPY pyproject.toml README.md ./
COPY src ./src
# [api] fastapi+uvicorn · [enhanced] sslyze, Wappalyzer, JWT, detect-secrets, nvdlib ·
# [apifuzz] schemathesis · python-gvm deja el módulo OpenVAS listo por si algún día hay GVM.
RUN pip install --no-cache-dir ".[api,enhanced,apifuzz]" python-gvm

# CLI por defecto; la web se levanta sobreescribiendo el entrypoint (ver compose):
#   uvicorn webvulnscanner.api:app --host 0.0.0.0 --port 8000
WORKDIR /reports
ENTRYPOINT ["webvulnscanner"]
CMD ["--help"]
