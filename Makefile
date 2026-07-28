COMPOSE := docker compose
EXPOSED_COMPOSE := $(COMPOSE) -f compose.yaml -f compose.expose.yaml
TEST_COMPOSE := $(COMPOSE) -p anva-tests
TEST_RUN := $(TEST_COMPOSE) --profile test run --rm --build test
CORPUS_COMPOSE := $(TEST_COMPOSE) -f compose.yaml -f compose.corpus.yaml

.PHONY: help up up-exposed down reset logs migrate migrations-check shell cli lock contracts contracts-check format format-check lint type unit integration corpus contract smoke coverage test test-down check ci

help:
	@echo "Anva development commands (all application tooling runs in Compose)"
	@echo "  make up            Build and start the internal-only stack"
	@echo "  make up-exposed    Build and start with documented host ports"
	@echo "  make check         Run formatting, lint, typing, and every test suite"
	@echo "  make contracts     Regenerate versioned OpenAPI, MCP, schemas, and examples"
	@echo "  make corpus        Ingest the sibling anva-test repo through a read-only mount"
	@echo "  make test-down     Remove the isolated test project"
	@echo "  make reset         Remove local containers and named data volumes"
	@echo "  make logs          Follow service logs"

up:
	$(COMPOSE) up --build -d

up-exposed:
	$(EXPOSED_COMPOSE) up --build -d

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down --volumes --remove-orphans

logs:
	$(COMPOSE) logs --follow api worker mcp postgres minio

migrate:
	$(COMPOSE) run --rm migrate

migrations-check:
	$(TEST_RUN) python -m anva.manage makemigrations --check --dry-run

shell:
	$(COMPOSE) run --rm api python -m anva.manage shell

cli:
	$(COMPOSE) --profile tools run --rm cli

lock:
	$(COMPOSE) --profile tools run --rm lock

contracts:
	$(TEST_RUN) python -m anva.contracts.generate --write --validate-examples

contracts-check:
	$(TEST_RUN) python -m anva.contracts.generate --check --validate-examples

format:
	$(TEST_RUN) ruff format .

format-check:
	$(TEST_RUN) ruff format --check .

lint:
	$(TEST_RUN) ruff check .

type:
	$(TEST_RUN) mypy src tests

unit:
	$(TEST_RUN) pytest -m unit

integration:
	$(TEST_RUN) pytest -m integration

corpus:
	$(CORPUS_COMPOSE) --profile test run --rm --build test pytest -m corpus

contract:
	$(TEST_RUN) pytest -m contract

smoke:
	$(TEST_RUN) pytest -m smoke

coverage:
	$(TEST_RUN) sh -c "coverage run -m pytest && coverage report"

test: unit integration contract smoke

test-down:
	$(TEST_COMPOSE) --profile test down --volumes --remove-orphans

check: format-check lint type migrations-check contracts-check coverage

ci: check
