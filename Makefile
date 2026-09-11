.DEFAULT_GOAL := help
PY ?= python

.PHONY: help install dev lint fmt test run-orchestrator run-worker demo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install (runtime only)
	$(PY) -m pip install -e .

dev: ## Install with dev extras
	$(PY) -m pip install -e ".[dev]"

lint: ## ruff check + format check
	ruff check .
	ruff format --check .

fmt: ## Auto-format
	ruff check --fix .
	ruff format .

test: ## Run tests
	pytest

run-orchestrator: ## Run the orchestrator locally
	SCANGRID_ROLE=orchestrator scangrid orchestrator --reload

run-worker: ## Run a worker locally (needs nmap)
	SCANGRID_ROLE=worker scangrid worker

demo: ## docker compose demo stack
	docker compose up --build

clean: ## Remove caches / build artefacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info var
	find . -name __pycache__ -type d -exec rm -rf {} +
