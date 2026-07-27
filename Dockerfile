# Imagen mínima para correr WebVulnScanner como CLI.
FROM python:3.12-slim

WORKDIR /app

# Instalar primero solo los metadatos para aprovechar la caché de capas.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Los reportes se escriben en /reports (montar como volumen).
WORKDIR /reports

ENTRYPOINT ["webvulnscanner"]
CMD ["--help"]
