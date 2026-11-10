.PHONY: help install dev test lint format typecheck check run api docker clean

help:  ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Instala el paquete (núcleo)
	pip install -e .

dev:  ## Instala con todas las extras (gui, api, dev)
	pip install -e ".[gui,api,dev]"

test:  ## Corre la suite de tests
	pytest

cov:  ## Tests con cobertura
	pytest --cov=webvulnscanner --cov-report=term-missing

lint:  ## Linter + formato (ruff)
	ruff check .
	ruff format --check .

format:  ## Formatea el código (ruff)
	ruff format .

typecheck:  ## Chequeo de tipos (mypy)
	mypy

check: lint typecheck test  ## lint + formato + tipos + tests (correr antes de cada push)

run:  ## Escaneo de ejemplo (make run DOMINIO=example.com)
	webvulnscanner $(DOMINIO)

api:  ## Levanta la API REST
	uvicorn webvulnscanner.api:app --reload

docker:  ## Construye la imagen Docker
	docker build -t webvulnscanner:2.0 .

clean:  ## Limpia cachés y reportes
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__ reporte_*.{txt,json,html,sarif}
