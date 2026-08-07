COMPOSE_PROJECT ?= anva
TEST_PROJECT ?= anva-tests
ANVA_IMAGE_REPOSITORY ?= anva
ANVA_VERSION ?= 0.1.0
ANVA_REVISION ?= $(shell git rev-parse --verify HEAD 2>/dev/null)
ANVA_IMAGE_REF := $(ANVA_IMAGE_REPOSITORY):$(ANVA_VERSION)
REHEARSAL_PROJECT ?= $(COMPOSE_PROJECT)-migration-rehearsal
override OPERATIONS_LOCK_CONTAINER := $(COMPOSE_PROJECT)-operations-lock
override REHEARSAL_COMPOSE := \
	ANVA_ENV=development \
	ANVA_DEBUG=false \
	ANVA_SECRET_KEY=rehearsal-only-secret-key \
	ANVA_TOKEN_PEPPER=rehearsal-only-token-pepper \
	ANVA_BOOTSTRAP_SECRET=rehearsal-only-bootstrap-secret \
	ANVA_DATABASE_URL=postgresql://anva_rehearsal:anva-rehearsal-only@postgres:5432/anva_rehearsal \
	ANVA_POSTGRES_DB=anva_rehearsal \
	ANVA_POSTGRES_USER=anva_rehearsal \
	ANVA_POSTGRES_PASSWORD=anva-rehearsal-only \
	ANVA_OBJECT_STORAGE_ENDPOINT=http://minio:9000 \
	ANVA_OBJECT_STORAGE_BUCKET=anva-rehearsal \
	ANVA_OBJECT_STORAGE_ACCESS_KEY=anva-rehearsal \
	ANVA_OBJECT_STORAGE_SECRET_KEY=anva-rehearsal-only \
	ANVA_MINIO_BUCKET=anva-rehearsal \
	ANVA_MINIO_ROOT_USER=anva-rehearsal \
	ANVA_MINIO_ROOT_PASSWORD=anva-rehearsal-only \
	docker compose -f compose.yaml -p $(REHEARSAL_PROJECT)
TRIVY_SOURCE_SKIPS := --skip-dirs /workspace/.git --skip-dirs /workspace/.secrets --skip-dirs /workspace/secrets --skip-dirs /workspace/backups --skip-dirs /workspace/release --skip-dirs /workspace/.venv --skip-dirs /workspace/.pytest_cache --skip-dirs /workspace/.mypy_cache --skip-dirs /workspace/.ruff_cache --skip-dirs /workspace/htmlcov --skip-files /workspace/.env
export ANVA_IMAGE_REPOSITORY ANVA_VERSION ANVA_REVISION
COMPOSE := docker compose -p $(COMPOSE_PROJECT)
EXPOSED_COMPOSE := $(COMPOSE) -f compose.yaml -f compose.expose.yaml
RELEASE_COMPOSE := $(COMPOSE) -f compose.yaml -f compose.release.yaml
TEST_COMPOSE := docker compose -p $(TEST_PROJECT)
TEST_RUN := $(TEST_COMPOSE) --profile test run --rm --build test
ACCEPTANCE_PROJECT ?= anva-acceptance
ACCEPTANCE_COMPOSE := docker compose -p $(ACCEPTANCE_PROJECT) -f compose.yaml -f compose.acceptance.yaml

.PHONY: help install-demo up up-exposed down uninstall uninstall-clean backup backup-verify restore migration-rehearsal rate-limit-cleanup release-build release-scan release-scan-gate release-manifest release-artifacts release-clean reset logs migrate migrations-check shell cli lock contracts contracts-check skills-render skills-package skills-check format format-check lint type unit integration acceptance-canonicalize acceptance-verify acceptance-down contract smoke browser coverage test test-down check ci

help:
	@echo "Anva development commands (all application tooling runs in Compose)"
	@echo "  make up            Build and start the internal-only stack"
	@echo "  make install-demo  Install, migrate, and seed a local demo with one command"
	@echo "  make up-exposed    Build and start with documented host ports"
	@echo "  make backup        Quiesce writers and back up PostgreSQL plus object storage"
	@echo "  make restore       Verify and restore a backup, then migrate"
	@echo "  make rate-limit-cleanup Delete one bounded batch of expired pre-auth counters"
	@echo "  make release-artifacts  Build wheel, SBOMs, scans, manifest, and checksums"
	@echo "  make release-scan-gate Fail on unwaived high/critical image vulnerabilities"
	@echo "  make uninstall     Remove services while preserving named data volumes"
	@echo "  make uninstall-clean  Remove services and all named installation data"
	@echo "  make check         Run formatting, lint, typing, and every test suite"
	@echo "  make contracts     Regenerate versioned OpenAPI, MCP, schemas, and examples"
	@echo "  make skills-check  Verify rendered skills, archives, checksums, and evals"
	@echo "  make browser       Run the browser-native product journey in Chromium"
	@echo "  make acceptance-canonicalize  Copy one pinned public corpus into an isolated volume"
	@echo "  make acceptance-verify  Verify the canonical corpus without the raw mount"
	@echo "  make acceptance-down  Remove only the acceptance project's ephemeral resources"
	@echo "  make test-down     Remove the isolated test project"
	@echo "  make reset         Remove local containers and named data volumes"
	@echo "  make logs          Follow service logs"

up:
	$(COMPOSE) up --build -d

install-demo:
	$(COMPOSE) up --build --wait
	$(COMPOSE) --profile demo run --rm --no-deps demo

up-exposed:
	$(EXPOSED_COMPOSE) up --build -d

down:
	$(COMPOSE) down

uninstall: down

uninstall-clean:
	$(COMPOSE) --profile demo --profile github --profile operations down --volumes --remove-orphans

backup:
	@set -eu; \
	lock_container="$(OPERATIONS_LOCK_CONTAINER)"; \
	if ! $(COMPOSE) --profile operations run -d --name "$$lock_container" \
		operations-lock >/dev/null; then \
		echo "Another backup, restore, or rehearsal is active for $(COMPOSE_PROJECT)." >&2; \
		exit 1; \
	fi; \
	running_writers=""; \
	cleanup() { \
		status=$$?; \
		trap - EXIT HUP INT TERM; \
		set +e; \
		resume_status=0; \
		if [ -n "$$running_writers" ]; then \
			$(COMPOSE) up -d $$running_writers; resume_status=$$?; \
		fi; \
		docker rm --force "$$lock_container" >/dev/null 2>&1 || true; \
		if [ "$$status" -eq 0 ] && [ "$$resume_status" -ne 0 ]; then \
			status=$$resume_status; \
		fi; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT; \
	trap 'exit 129' HUP; \
	trap 'exit 130' INT; \
	trap 'exit 143' TERM; \
	$(COMPOSE) --profile operations run --rm --no-deps operations-guard; \
	backup_generation="$$(date -u +%Y%m%dT%H%M%SZ)-$$$$"; \
	export ANVA_BACKUP_GENERATION="$$backup_generation"; \
	for service in $$($(COMPOSE) ps --services --status running); do \
		case "$$service" in \
			api|worker|github-worker|mcp|mcp-read-only) \
				running_writers="$$running_writers $$service" ;; \
		esac; \
	done; \
	if [ -n "$$running_writers" ]; then $(COMPOSE) stop $$running_writers; fi; \
	$(COMPOSE) --profile operations run --rm backup-database; \
	$(COMPOSE) --profile operations run --rm backup-objects; \
	$(COMPOSE) --profile operations run --rm backup-manifest; \
	$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup --generation "$$backup_generation" verify; \
	$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup --generation "$$backup_generation" activate; \
	echo "Activated backup generation $$backup_generation"

backup-verify:
	@set -eu; \
	lock_container="$(OPERATIONS_LOCK_CONTAINER)"; \
	if ! $(COMPOSE) --profile operations run -d --name "$$lock_container" \
		operations-lock >/dev/null; then \
		echo "Another backup, restore, or rehearsal is active for $(COMPOSE_PROJECT)." >&2; \
		exit 1; \
	fi; \
	cleanup() { \
		status=$$?; trap - EXIT HUP INT TERM; \
		docker rm --force "$$lock_container" >/dev/null 2>&1 || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT; \
	trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	backup_generation="$$( \
		$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup current \
	)"; \
	$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup --generation "$$backup_generation" verify

restore:
	@set -eu; \
	lock_container="$(OPERATIONS_LOCK_CONTAINER)"; \
	if ! $(COMPOSE) --profile operations run -d --name "$$lock_container" \
		operations-lock >/dev/null; then \
		echo "Another backup, restore, or rehearsal is active for $(COMPOSE_PROJECT)." >&2; \
		exit 1; \
	fi; \
	cleanup() { \
		status=$$?; trap - EXIT HUP INT TERM; \
		docker rm --force "$$lock_container" >/dev/null 2>&1 || true; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT; \
	trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(COMPOSE) --profile operations run --rm --no-deps operations-guard; \
	backup_generation="$$( \
		$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup current \
	)"; \
	$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup --generation "$$backup_generation" verify; \
	export ANVA_BACKUP_GENERATION="$$backup_generation"; \
	running_writers=""; \
	for service in $$($(COMPOSE) ps --services --status running); do \
		case "$$service" in \
			api|worker|github-worker|mcp|mcp-read-only) \
				running_writers="$$running_writers $$service" ;; \
		esac; \
	done; \
	if [ -n "$$running_writers" ]; then $(COMPOSE) stop $$running_writers; fi; \
	if $(COMPOSE) --profile operations run --rm restore-database && \
		$(COMPOSE) --profile operations run --rm restore-objects && \
		$(COMPOSE) run --rm --no-deps migrate; then \
		if [ -n "$$running_writers" ]; then $(COMPOSE) up -d $$running_writers; fi; \
	else \
		echo "Restore failed; previously running writers remain stopped for operator recovery." >&2; \
		exit 1; \
	fi

migration-rehearsal:
	@set -eu; \
	lock_container="$(OPERATIONS_LOCK_CONTAINER)"; \
	if ! $(COMPOSE) --profile operations run -d --name "$$lock_container" \
		operations-lock >/dev/null; then \
		echo "Another backup, restore, or rehearsal is active for $(COMPOSE_PROJECT)." >&2; \
		exit 1; \
	fi; \
	running_writers=""; \
	rehearsal_created=false; \
	cleanup() { \
		status=$$?; \
		trap - EXIT HUP INT TERM; \
		set +e; \
		resume_status=0; cleanup_status=0; \
		if [ -n "$$running_writers" ]; then \
			$(COMPOSE) up -d $$running_writers; resume_status=$$?; \
		fi; \
		if [ "$$rehearsal_created" = true ]; then \
			$(REHEARSAL_COMPOSE) --profile operations down --volumes \
				--remove-orphans >/dev/null 2>&1; cleanup_status=$$?; \
		fi; \
		docker rm --force "$$lock_container" >/dev/null 2>&1 || true; \
		if [ "$$status" -eq 0 ] && [ "$$resume_status" -ne 0 ]; then \
			status=$$resume_status; \
		fi; \
		if [ "$$status" -eq 0 ] && [ "$$cleanup_status" -ne 0 ]; then \
			status=$$cleanup_status; \
		fi; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT; \
	trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	if [ "$(REHEARSAL_PROJECT)" = "$(COMPOSE_PROJECT)" ]; then \
		echo "REHEARSAL_PROJECT must differ from COMPOSE_PROJECT" >&2; exit 1; \
	fi; \
	if [ -n "$$(docker ps -aq --filter label=com.docker.compose.project=$(REHEARSAL_PROJECT))$$(docker volume ls -q --filter label=com.docker.compose.project=$(REHEARSAL_PROJECT))$$(docker network ls -q --filter label=com.docker.compose.project=$(REHEARSAL_PROJECT))" ]; then \
		echo "Refusing to reuse non-empty rehearsal project $(REHEARSAL_PROJECT)" >&2; exit 1; \
	fi; \
	$(COMPOSE) --profile operations run --rm --no-deps operations-guard; \
	backup_generation="$$(date -u +%Y%m%dT%H%M%SZ)-$$$$"; \
	export ANVA_BACKUP_GENERATION="$$backup_generation"; \
	for service in $$($(COMPOSE) ps --services --status running); do \
		case "$$service" in \
			api|worker|github-worker|mcp|mcp-read-only) \
				running_writers="$$running_writers $$service" ;; \
		esac; \
	done; \
	if [ -n "$$running_writers" ]; then $(COMPOSE) stop $$running_writers; fi; \
	$(COMPOSE) --profile operations run --rm backup-database; \
	$(COMPOSE) --profile operations run --rm backup-objects; \
	$(COMPOSE) --profile operations run --rm backup-manifest; \
	$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup --generation "$$backup_generation" verify; \
	$(COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest \
		backup --directory /backup --generation "$$backup_generation" activate; \
	if [ -n "$$running_writers" ]; then $(COMPOSE) up -d $$running_writers; fi; \
	running_writers=""; \
	rehearsal_created=true; \
	$(REHEARSAL_COMPOSE) up -d --wait postgres minio; \
	$(REHEARSAL_COMPOSE) run --rm --no-deps minio-init; \
	ANVA_BACKUP_GENERATION="$$backup_generation" $(REHEARSAL_COMPOSE) \
		--profile operations run --rm restore-database; \
	ANVA_BACKUP_GENERATION="$$backup_generation" $(REHEARSAL_COMPOSE) \
		--profile operations run --rm restore-objects; \
	$(REHEARSAL_COMPOSE) run --rm --no-deps migrate \
		python -m anva.manage migrate core 0019 --noinput; \
	$(REHEARSAL_COMPOSE) run --rm --no-deps migrate; \
	echo "Migration reversal/forward rehearsal passed in isolated project $(REHEARSAL_PROJECT)"

rate-limit-cleanup:
	$(COMPOSE) --profile tools run --rm cli \
		python -m anva.entrypoints.cli maintenance purge-preauth-rate-buckets

release-clean:
	$(RELEASE_COMPOSE) --profile release run --rm --build release-builder \
		sh -eu -c 'find /release -maxdepth 1 -type f ! -name .gitkeep -delete'

release-build: release-clean
	$(COMPOSE) build api
	$(RELEASE_COMPOSE) --profile release run --rm --build release-builder \
		sh -eu -c 'uv build --python /app/.venv/bin/python \
		--no-build-isolation --offline --wheel --out-dir /release && \
		python -m anva.entrypoints.cli skills package --output /tmp/anva-skills-dist && \
		python -m anva.entrypoints.cli skills verify --output /tmp/anva-skills-dist && \
		cp /tmp/anva-skills-dist/anva-codex-skills-1.0.0.tar.gz /release/ && \
		cp /tmp/anva-skills-dist/anva-claude-skills-1.0.0.tar.gz /release/ && \
		cp docs/security/vulnerability-exceptions.json /release/ && \
		cp docs/releases/mvp-013.md /release/RELEASE_NOTES.md'

release-scan:
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		image --format spdx-json --output /release/anva-image.spdx.json \
		$(ANVA_IMAGE_REF)
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		image --format cyclonedx --output /release/anva-image.cyclonedx.json \
		$(ANVA_IMAGE_REF)
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		image --scanners vuln --format json \
		--output /release/anva-image-vulnerabilities.json \
		$(ANVA_IMAGE_REF)
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		filesystem --scanners vuln,secret,misconfig --format json \
		$(TRIVY_SOURCE_SKIPS) --output /release/anva-source-security.json /workspace

release-scan-gate: release-scan
	$(RELEASE_COMPOSE) --profile release run --rm release-builder \
		python -m anva.release exceptions \
		--input /workspace/docs/security/vulnerability-exceptions.json \
		--report /release/anva-image-vulnerabilities.json \
		--output /release/.trivyignore
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		image --scanners vuln --severity HIGH,CRITICAL \
		--ignorefile /release/.trivyignore --exit-code 1 \
		$(ANVA_IMAGE_REF)
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		filesystem --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
		$(TRIVY_SOURCE_SKIPS) --exit-code 1 /workspace

release-manifest:
	@test -z "$$(git status --porcelain=v1 --untracked-files=all)" || \
		(echo "release-manifest requires a clean exact commit" >&2; exit 1)
	@source_commit=$$(git rev-parse HEAD); \
	image_id=$$(docker image inspect \
		$(ANVA_IMAGE_REF) --format '{{.Id}}'); \
	image_revision=$$(docker image inspect \
		$(ANVA_IMAGE_REF) --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'); \
	if [ "$$image_revision" != "$$source_commit" ]; then \
		echo "Image OCI revision does not match the exact source commit" >&2; exit 1; \
	fi; \
	$(RELEASE_COMPOSE) --profile release run --rm release-builder \
		python -m anva.release manifest --directory /release \
		--source-commit "$$source_commit" \
		--image-reference "$(ANVA_IMAGE_REF)" \
		--image-id "$$image_id"

release-artifacts: release-build release-scan release-scan-gate release-manifest

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

skills-render:
	$(TEST_RUN) python -m anva.entrypoints.cli skills render

skills-package:
	$(TEST_RUN) python -m anva.entrypoints.cli skills package --output packages/anva-skills/dist

skills-check:
	$(TEST_RUN) python -m anva.entrypoints.cli skills check

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

acceptance-canonicalize:
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm --build acceptance-adapter

acceptance-verify:
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm acceptance-runner

acceptance-down:
	$(ACCEPTANCE_COMPOSE) --profile acceptance down --volumes --remove-orphans

contract:
	$(TEST_RUN) pytest -m contract

smoke:
	$(TEST_RUN) pytest -m smoke

browser:
	$(TEST_COMPOSE) --profile test --profile browser run --rm --build browser-test pytest -m browser

coverage:
	$(TEST_RUN) sh -c "coverage run -m pytest && coverage report"

test: unit integration contract smoke

test-down:
	$(TEST_COMPOSE) --profile test --profile browser down --volumes --remove-orphans

check: format-check lint type migrations-check contracts-check skills-check coverage browser

ci: check
