SHELL := /bin/bash

.PHONY: install dev test lint typecheck verify compose-up compose-down compose-logs compose-ps

install:
	corepack enable
	pnpm install
	cd apps/api && uv sync --all-groups

dev:
	pnpm dev

test:
	pnpm test
	cd apps/api && uv run pytest

lint:
	pnpm lint
	cd apps/api && uv run ruff check .

typecheck:
	pnpm typecheck
	cd apps/api && uv run mypy app

verify:
	python3 scripts/verify-scaffold.py

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f

compose-ps:
	docker compose ps
