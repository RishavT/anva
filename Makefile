COMPOSE_PROJECT ?= anva
TEST_PROJECT ?= anva-tests
ANVA_IMAGE_REPOSITORY ?= anva
ANVA_VERSION ?= 0.1.6
ANVA_REVISION ?= $(shell git rev-parse --verify HEAD 2>/dev/null)
ANVA_SOURCE ?= https://github.com/rishavt/anva
SOURCE_DATE_EPOCH ?= $(shell git show -s --format=%ct HEAD 2>/dev/null)
ANVA_IMAGE_SHA256 ?=
ANVA_BUILD_INPUT_SHA256 ?=
ANVA_IMAGE_BUILD_INPUT_SHA256 := $(if $(strip $(ANVA_BUILD_INPUT_SHA256)),$(ANVA_BUILD_INPUT_SHA256),0000000000000000000000000000000000000000000000000000000000000000)
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
export ANVA_IMAGE_REPOSITORY ANVA_VERSION ANVA_REVISION ANVA_SOURCE SOURCE_DATE_EPOCH ANVA_IMAGE_SHA256 ANVA_BUILD_INPUT_SHA256
export ANVA_ACCEPTANCE_UID ANVA_ACCEPTANCE_GID
export ANVA_DRILL_IMAGE ANVA_DRILL_SOURCE_COMMIT
export ANVA_DRILL_PRODUCT_SOURCE_COMMIT
COMPOSE := docker compose -p $(COMPOSE_PROJECT)
EXPOSED_COMPOSE := $(COMPOSE) -f compose.yaml -f compose.expose.yaml
RELEASE_COMPOSE := $(COMPOSE) -f compose.yaml -f compose.release.yaml
TEST_COMPOSE := docker compose -p $(TEST_PROJECT)
TEST_RUN := $(TEST_COMPOSE) --profile test run --rm --build test
ACCEPTANCE_PROJECT ?= anva-acceptance
ACCEPTANCE_CASE_COMPOSE = $(if $(strip $(ANVA_ACCEPTANCE_CASE_FILE)),-f compose.acceptance.case.yaml,)
ACCEPTANCE_COMPOSE = docker compose -p $(ACCEPTANCE_PROJECT) -f compose.yaml -f compose.acceptance.yaml $(ACCEPTANCE_CASE_COMPOSE)
DRILL_PROJECT ?= anva-issue44-drill
ANVA_DRILL_IMAGE ?=
ANVA_DRILL_SOURCE_COMMIT ?=
ANVA_DRILL_PRODUCT_SOURCE_COMMIT ?=
DRILL_COMPOSE := docker compose -p $(DRILL_PROJECT) -f compose.yaml -f compose.drill.yaml
DRILL_FAULT_COMPOSE := $(DRILL_COMPOSE) -f compose.drill.restore-fault.yaml

.PHONY: help install-demo up up-exposed down uninstall uninstall-clean backup backup-verify restore migration-rehearsal rate-limit-cleanup decommission-cleanup-status drill-network-preflight drill-up drill-probes drill-evidence-template drill-evidence-record drill-evidence-decision-proposal drill-evidence-cleanup drill-evidence-provisional-validate drill-evidence-finalize drill-evidence-final-validate drill-restore-fault drill-storage-interrupt drill-storage-resume drill-decommission-retry drill-down release-image-build release-image-oci release-package-files release-build release-scan release-scan-gate release-manifest release-artifacts release-clean reset logs migrate migrations-check shell cli lock contracts contracts-check skills-render skills-package skills-check format format-check lint type unit integration acceptance-identity-preflight acceptance-canonicalize acceptance-verify acceptance-launch-manifest acceptance-start acceptance-review-request acceptance-review-submit acceptance-finalize acceptance-down contract smoke browser coverage test test-down check ci

help:
	@echo "Anva development commands (all application tooling runs in Compose)"
	@echo "  make up            Build and start the internal-only stack"
	@echo "  make install-demo  Install, migrate, and seed a local demo with one command"
	@echo "  make up-exposed    Build and start with documented host ports"
	@echo "  make backup        Quiesce writers and back up PostgreSQL plus object storage"
	@echo "  make restore       Verify and restore a backup, then migrate"
	@echo "  make rate-limit-cleanup Delete one bounded batch of expired pre-auth counters"
	@echo "  make decommission-cleanup-status Inspect one exact failed cleanup (operator credential required)"
	@echo "  make drill-network-preflight Validate the disposable #44 proxy subnet before startup"
	@echo "  make drill-up      Start the synthetic #44 HTTPS drill harness (not the human drill)"
	@echo "  make drill-down    Remove only the disposable #44 drill project and volumes"
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
	@echo "  make acceptance-launch-manifest  Generate the required immutable Docker launch contract"
	@echo "  make acceptance-start  Generate/reuse the launch contract, then run until review"
	@echo "  make acceptance-review-request  Seal an independent evaluator handoff"
	@echo "  make acceptance-review-submit  Submit an externally authored evaluator result"
	@echo "  make acceptance-finalize  Atomically seal public deterministic results"
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

decommission-cleanup-status:
	@test -n "$(ORGANIZATION_ID)" && test -n "$(RUN_ID)" || \
		(echo "ORGANIZATION_ID and RUN_ID are required" >&2; exit 2)
	$(COMPOSE) --profile operations run --rm decommission-cleanup-operator \
		python -m anva.entrypoints.cli maintenance retry-decommission-cleanup \
		--organization-id "$(ORGANIZATION_ID)" --run-id "$(RUN_ID)" --status

drill-network-preflight:
	@set -eu; \
		test "$(DRILL_PROJECT)" != "anva" || (echo "DRILL_PROJECT must be disposable" >&2; exit 2); \
		task="$$(mktemp -d "$${TMPDIR:-/tmp}/anva-issue44-preflight.XXXXXXXX")"; \
		trap 'find "$$task" -type f -delete; rmdir "$$task"' EXIT HUP INT TERM; \
		docker network inspect $$(docker network ls -q) > "$$task/networks.json"; \
		ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" ANVA_DRILL_INPUT_DIR="$$task" \
		$(DRILL_COMPOSE) --profile drill-tools run --rm --no-deps drill-tool \
			network-preflight --subnet "$${ANVA_DRILL_SUBNET:-172.31.44.0/24}" \
			--proxy-ip "$${ANVA_DRILL_PROXY_IP:-172.31.44.10}" \
			--owned-network "$(DRILL_PROJECT)_backend" \
			--networks-json /drill-input/networks.json

drill-up: drill-network-preflight
	DRILL_PROJECT="$(DRILL_PROJECT)" sh deploy/drill/drill-up.sh

drill-probes:
	$(DRILL_COMPOSE) run --rm drill-scrape
	$(DRILL_COMPOSE) run --rm drill-untrusted-probe

drill-evidence-template:
	@test -n "$(DRILL_ID)" || (echo "DRILL_ID is required" >&2; exit 2)
	@test -n "$(ANVA_DRILL_IMAGE)" && test -n "$(ANVA_DRILL_SOURCE_COMMIT)" && test -n "$(ANVA_DRILL_PRODUCT_SOURCE_COMMIT)" || (echo "exact image, harness source, and product source are required" >&2; exit 2)
	@mkdir -p "$${ANVA_DRILL_EVIDENCE_DIR:-evidence/issue-044}"
	@image_revision="$$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$(ANVA_DRILL_IMAGE)")"; \
		test "$$image_revision" = "$(ANVA_DRILL_PRODUCT_SOURCE_COMMIT)" || { echo "product source does not match immutable image revision" >&2; exit 2; }; \
		ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" $(DRILL_COMPOSE) --profile drill-tools run --rm --no-deps drill-tool create-evidence \
		--drill-id "$(DRILL_ID)" \
		--source-revision "$(ANVA_DRILL_SOURCE_COMMIT)" \
		--product-version "$(ANVA_VERSION)" \
		--product-source-commit "$(ANVA_DRILL_PRODUCT_SOURCE_COMMIT)" \
		--operator-source-commit "$(ANVA_DRILL_PRODUCT_SOURCE_COMMIT)" \
		--operator-cli-in-product \
		--image-digest "$${ANVA_DRILL_IMAGE#*@}" \
		--output-dir /evidence

drill-evidence-provisional-validate:
	@test -n "$(EVIDENCE_FILE)" || (echo "EVIDENCE_FILE is required" >&2; exit 2)
	ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" $(DRILL_COMPOSE) --profile drill-tools run --rm --no-deps drill-tool \
		validate-provisional "/evidence/$$(basename "$(EVIDENCE_FILE)")"

drill-evidence-record:
	@$(MAKE) drill-evidence-event EVENT_COMMAND=record-check EVENT_JSON="$(CHECK_JSON)" EVIDENCE_FILE="$(EVIDENCE_FILE)"

drill-evidence-decision-proposal:
	@$(MAKE) drill-evidence-event EVENT_COMMAND=record-decision-proposal EVENT_JSON="$(DECISION_JSON)" EVIDENCE_FILE="$(EVIDENCE_FILE)"

drill-evidence-cleanup:
	@$(MAKE) drill-evidence-event EVENT_COMMAND=record-cleanup EVENT_JSON="$(CLEANUP_JSON)" EVIDENCE_FILE="$(EVIDENCE_FILE)"

drill-evidence-finalize:
	@set -eu; \
		test -n "$(EVIDENCE_FILE)" && test -f "$(EVIDENCE_FILE)" && test -n "$(ANCHOR_JSON)" && test -f "$(ANCHOR_JSON)" || (echo "exact evidence and anchor files are required" >&2; exit 2); \
		test -n "$(GH_CONFIG_DIR)" && test -d "$(GH_CONFIG_DIR)" || (echo "GH_CONFIG_DIR is required" >&2; exit 2); \
		gh_bin="$$(command -v gh)"; test -x "$$gh_bin" || (echo "gh executable is required" >&2; exit 2); \
		ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" ANVA_DRILL_INPUT_DIR="$$(dirname "$(ANCHOR_JSON)")" \
		ANVA_DRILL_GH_CONFIG_DIR="$(GH_CONFIG_DIR)" ANVA_DRILL_GH_BIN="$$gh_bin" \
		$(DRILL_COMPOSE) --profile drill-finalize run --rm --no-deps drill-finalizer \
			finalize "/evidence/$$(basename "$(EVIDENCE_FILE)")" --anchor-json "/drill-input/$$(basename "$(ANCHOR_JSON)")"
drill-evidence-final-validate:
	@set -eu; \
		test -n "$(EVIDENCE_FILE)" && test -f "$(EVIDENCE_FILE)" || (echo "exact evidence file is required" >&2; exit 2); \
		test -n "$(GH_CONFIG_DIR)" && test -d "$(GH_CONFIG_DIR)" || (echo "GH_CONFIG_DIR is required" >&2; exit 2); \
		gh_bin="$$(command -v gh)"; test -x "$$gh_bin" || (echo "gh executable is required" >&2; exit 2); \
		task="$$(mktemp -d "$${TMPDIR:-/tmp}/anva-issue44-final.XXXXXXXX")"; \
		trap 'rmdir "$$task"' EXIT HUP INT TERM; \
		ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" ANVA_DRILL_INPUT_DIR="$$task" \
		ANVA_DRILL_GH_CONFIG_DIR="$(GH_CONFIG_DIR)" ANVA_DRILL_GH_BIN="$$gh_bin" \
		$(DRILL_COMPOSE) --profile drill-finalize run --rm --no-deps drill-finalizer \
			validate-final "/evidence/$$(basename "$(EVIDENCE_FILE)")"

.PHONY: drill-evidence-event
drill-evidence-event:
	@set -eu; \
		test -n "$(EVIDENCE_FILE)" && test -n "$(EVENT_JSON)" && test -f "$(EVENT_JSON)" || (echo "evidence and event JSON are required" >&2; exit 2); \
		task="$$(mktemp -d "$${TMPDIR:-/tmp}/anva-issue44-event.XXXXXXXX")"; \
		trap 'find "$$task" -type f -delete; rmdir "$$task"' EXIT HUP INT TERM; \
		cp "$(EVENT_JSON)" "$$task/event.json"; \
		ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" ANVA_DRILL_INPUT_DIR="$$task" \
		$(DRILL_COMPOSE) --profile drill-tools run --rm --no-deps drill-tool \
			$(EVENT_COMMAND) "/evidence/$$(basename "$(EVIDENCE_FILE)")" $${EVENT_FLAG:---event-json} /drill-input/event.json

drill-restore-fault:
	@set -eu; \
		generation="$$( $(DRILL_COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest backup --directory /backup current )"; \
		$(DRILL_COMPOSE) --profile operations run --rm --entrypoint anva backup-manifest backup --directory /backup --generation "$$generation" verify; \
		writers="$$( $(DRILL_COMPOSE) ps --services --status running | sed -n '/^api$$\|^worker$$\|^github-worker$$\|^mcp$$\|^mcp-read-only$$/p' )"; \
		test -n "$$writers" && $(DRILL_COMPOSE) stop $$writers || true; \
		task="$$(mktemp -d "$${TMPDIR:-/tmp}/anva-issue44-restore.XXXXXXXX")"; \
		trap 'find "$$task" -type f -delete; rmdir "$$task"' EXIT HUP INT TERM; \
		set +e; ANVA_BACKUP_GENERATION="$$generation" $(DRILL_FAULT_COMPOSE) --profile operations run --rm restore-objects >"$$task/restore.log" 2>&1; status=$$?; set -e; \
		resumed="$$( $(DRILL_COMPOSE) ps --services --status running | sed -n '/^api$$\|^worker$$\|^github-worker$$\|^mcp$$\|^mcp-read-only$$/p' )"; \
		sh deploy/drill/verify-restore-fault.sh "$$status" "$$task/restore.log" "$$resumed" \
			"$(DRILL_PROJECT)" "$(ANVA_DRILL_IMAGE)"

drill-storage-interrupt:
	$(DRILL_COMPOSE) stop minio

drill-storage-resume:
	$(DRILL_COMPOSE) up -d --wait minio
	$(DRILL_COMPOSE) run --rm --no-deps minio-init

drill-decommission-retry:
	@test -n "$(ORGANIZATION_ID)" && test -n "$(RUN_ID)" && test -n "$(EXPECTED_REQUEST_HASH)" && test -n "$(EXPECTED_ATTEMPT)" || \
		(echo "exact retry selectors are required" >&2; exit 2)
	ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" $(DRILL_COMPOSE) --profile drill-tools run --rm drill-decommission-operator \
		python -m anva.entrypoints.cli maintenance retry-decommission-cleanup \
		--organization-id "$(ORGANIZATION_ID)" --run-id "$(RUN_ID)" \
		--expected-request-hash "$(EXPECTED_REQUEST_HASH)" --expected-attempt "$(EXPECTED_ATTEMPT)" \
		--request-id "$(REQUEST_ID)" --confirm "$(CONFIRMATION)"

drill-down:
	@test "$(DRILL_PROJECT)" != "anva" || (echo "refusing non-disposable project" >&2; exit 2)
	$(DRILL_COMPOSE) --profile drill-tools --profile operations down --volumes --remove-orphans

release-clean:
	$(RELEASE_COMPOSE) --profile release run --rm --build release-builder \
		sh -eu -c 'find /release -maxdepth 1 -type f ! -name .gitkeep -delete'

release-image-build:
	ANVA_BUILD_INPUT_SHA256=$(ANVA_IMAGE_BUILD_INPUT_SHA256) \
		docker buildx bake -f compose.yaml api \
		--set api.output=type=docker,rewrite-timestamp=true

release-image-oci:
	@test -n "$(ANVA_OCI_OUTPUT)"
	ANVA_BUILD_INPUT_SHA256=$(ANVA_IMAGE_BUILD_INPUT_SHA256) \
		docker buildx bake --allow=fs.write=$(dir $(ANVA_OCI_OUTPUT)) -f compose.yaml api \
		$(ANVA_OCI_BUILD_FLAGS) \
		--set api.platform=linux/amd64 \
		--set api.output=type=oci,dest=$(ANVA_OCI_OUTPUT),rewrite-timestamp=true

release-package-files: release-clean
	$(RELEASE_COMPOSE) --profile release run --rm --build release-builder \
		sh -eu -c 'uv build --python /app/.venv/bin/python \
		--no-build-isolation --offline --wheel --out-dir /release && \
		python -m anva.release cleanup-uv-build --directory /release && \
		python -m anva.entrypoints.cli skills package --output /tmp/anva-skills-dist && \
		python -m anva.entrypoints.cli skills verify --output /tmp/anva-skills-dist && \
		cp /tmp/anva-skills-dist/anva-codex-skills-1.0.0.tar.gz /release/ && \
		cp /tmp/anva-skills-dist/anva-claude-skills-1.0.0.tar.gz /release/ && \
		cp docs/releases/v0.1.6.md /release/RELEASE_NOTES.md'
	@set -eu; \
	temporary_archive="release/.anva-install-$(ANVA_VERSION).tar"; \
	trap 'rm -f "$$temporary_archive"' 0 1 2 15; \
	git archive --format=tar --prefix="anva-$(ANVA_VERSION)/" \
		--output "$$temporary_archive" HEAD; \
	gzip -n -c "$$temporary_archive" > \
		"release/anva-install-$(ANVA_VERSION).tar.gz"

release-build: release-image-build release-package-files

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

release-scan-gate:
	@test -n "$(ANVA_RELEASE_RISK_DECISION_INPUT)" || { echo "ANVA_RELEASE_RISK_DECISION_INPUT is required" >&2; exit 2; }
	@test -f "$(ANVA_RELEASE_RISK_DECISION_INPUT)" || { echo "Exact candidate risk decision input is required" >&2; exit 2; }
	@test "$(ANVA_RELEASE_RISK_DECISION_INPUT)" != "release/vulnerability-risk-acceptance.json" || { echo "Risk decision input must be external to release outputs" >&2; exit 2; }
	@test -n "$(ANVA_RELEASE_IMAGE_REFERENCE)" || { echo "ANVA_RELEASE_IMAGE_REFERENCE is required" >&2; exit 2; }
	@test -n "$(ANVA_RELEASE_IMAGE_ID)" || { echo "ANVA_RELEASE_IMAGE_ID is required" >&2; exit 2; }
	@test -n "$(ANVA_GITHUB_RUN_ID)" || { echo "ANVA_GITHUB_RUN_ID is required" >&2; exit 2; }
	@test -n "$(ANVA_PROPOSAL_SHA256)" || { echo "ANVA_PROPOSAL_SHA256 is required" >&2; exit 2; }
	@test -n "$(ANVA_APPROVAL_RECORD_SHA256)" || { echo "ANVA_APPROVAL_RECORD_SHA256 is required" >&2; exit 2; }
	@test -n "$(ANVA_WORKFLOW_REPOSITORY)" || { echo "ANVA_WORKFLOW_REPOSITORY is required" >&2; exit 2; }
	@test -n "$(ANVA_WORKFLOW_REF)" || { echo "ANVA_WORKFLOW_REF is required" >&2; exit 2; }
	@set -eu; \
	staged=release/.vulnerability-risk-acceptance.input.json; \
	canonical=release/vulnerability-risk-acceptance.json; \
	rm -f "$$staged" "$$canonical"; \
	trap 'rm -f "$$staged"' EXIT; \
	cp "$(ANVA_RELEASE_RISK_DECISION_INPUT)" "$$staged"; \
	$(RELEASE_COMPOSE) --profile release run --rm release-builder \
		python -m anva.release decision-ignore \
		--decision /release/.vulnerability-risk-acceptance.input.json \
		--report /release/anva-image-vulnerabilities.json \
		--source-commit "$(ANVA_REVISION)" \
		--image-reference "$(ANVA_RELEASE_IMAGE_REFERENCE)" \
		--image-digest "$(ANVA_RELEASE_IMAGE_ID)" \
		--github-run-id "$(ANVA_GITHUB_RUN_ID)" \
		--proposal-sha256 "$(ANVA_PROPOSAL_SHA256)" \
		--approval-record-sha256 "$(ANVA_APPROVAL_RECORD_SHA256)" \
		--workflow-repository "$(ANVA_WORKFLOW_REPOSITORY)" \
		--workflow-ref "$(ANVA_WORKFLOW_REF)" \
		--output /release/.trivyignore; \
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		image --scanners vuln --severity HIGH,CRITICAL \
		--ignorefile /release/.trivyignore --exit-code 1 \
		$(ANVA_IMAGE_REF); \
	$(RELEASE_COMPOSE) --profile release run --rm release-scanner \
		filesystem --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
		$(TRIVY_SOURCE_SKIPS) --exit-code 1 /workspace; \
	$(RELEASE_COMPOSE) --profile release run --rm release-builder \
		rm -f /release/.trivyignore; \
	mv "$$staged" "$$canonical"; \
	trap - EXIT

release-manifest:
	@set -eu; \
	source_commit=$$(git rev-parse HEAD); \
	image_id="$${ANVA_RELEASE_IMAGE_ID:-$$(docker image inspect \
		$(ANVA_IMAGE_REF) --format '{{.Id}}')}"; \
	image_reference="$${ANVA_RELEASE_IMAGE_REFERENCE:-$(ANVA_IMAGE_REF)}"; \
	image_revision=$$(docker image inspect \
		$(ANVA_IMAGE_REF) --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'); \
	if [ "$$image_revision" != "$$source_commit" ]; then \
		echo "Image OCI revision does not match the exact source commit" >&2; exit 1; \
	fi; \
	$(RELEASE_COMPOSE) --profile release run --rm release-builder \
		python -m anva.release manifest --directory /release \
		--source-commit "$$source_commit" \
		--image-reference "$$image_reference" \
		--image-id "$$image_id"; \
	status_file=$$(mktemp); trap 'rm -f "$$status_file"' 0 1 2 15; \
	git status --porcelain=v1 -z --untracked-files=all --ignored=matching \
		> "$$status_file"; \
	$(RELEASE_COMPOSE) --profile release run --rm -T release-builder \
		python -m anva.release verify --directory /release \
		--worktree-status /dev/stdin --release-path release \
		--source-commit "$$source_commit" \
		--image-reference "$$image_reference" \
		--image-id "$$image_id" < "$$status_file"

release-artifacts:
	+$(MAKE) release-build
	+$(MAKE) release-scan
	+$(MAKE) release-scan-gate
	+$(MAKE) release-manifest

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

acceptance-identity-preflight:
	@uid="$${ANVA_ACCEPTANCE_UID:-}"; gid="$${ANVA_ACCEPTANCE_GID:-}"; \
	if { test -n "$$uid" && test -z "$$gid"; } || { test -z "$$uid" && test -n "$$gid"; }; then \
		echo "ANVA_ACCEPTANCE_UID and ANVA_ACCEPTANCE_GID must be supplied together" >&2; exit 2; \
	fi; \
	if test -n "$$uid"; then \
		case "$$uid" in *[!0-9]*|0*) \
			echo "ANVA_ACCEPTANCE_UID and ANVA_ACCEPTANCE_GID must be positive numeric IDs" >&2; exit 2 ;; \
		esac; \
		case "$$gid" in *[!0-9]*|0*) \
			echo "ANVA_ACCEPTANCE_UID and ANVA_ACCEPTANCE_GID must be positive numeric IDs" >&2; exit 2 ;; \
		esac; \
	fi

acceptance-canonicalize: acceptance-identity-preflight
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm --build acceptance-adapter

acceptance-verify: acceptance-identity-preflight
	@test -n "$(ANVA_ACCEPTANCE_MANIFEST_SHA256)" || { echo "ANVA_ACCEPTANCE_MANIFEST_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_SOURCE_FINGERPRINT)" || { echo "ANVA_ACCEPTANCE_SOURCE_FINGERPRINT is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256)" || { echo "ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256 is required"; exit 2; }
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm acceptance-runner

acceptance-launch-manifest: acceptance-identity-preflight
	@test -n "$(ANVA_REVISION)" || { echo "ANVA_REVISION is required"; exit 2; }
	@test -n "$(ANVA_IMAGE_SHA256)" || { echo "ANVA_IMAGE_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_BUILD_INPUT_SHA256)" || { echo "ANVA_BUILD_INPUT_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)" || { echo "ANVA_ACCEPTANCE_LAUNCH_MANIFEST is the required protected host output path"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_STATE_DIR)" || { echo "ANVA_ACCEPTANCE_STATE_DIR is required for protected generator inputs"; exit 2; }
	@set -eu; \
	manifest="$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)"; \
	case "$$manifest" in /*) ;; *) echo "ANVA_ACCEPTANCE_LAUNCH_MANIFEST must be an absolute path" >&2; exit 2 ;; esac; \
	if test -e "$$manifest" || test -L "$$manifest"; then \
		test -f "$$manifest" && test ! -L "$$manifest" || { echo "Existing launch manifest must be a regular non-symlink file" >&2; exit 2; }; \
		test -z "$$(find "$$manifest" -maxdepth 0 -perm /222 -print -quit)" || { echo "Existing launch manifest must be read-only; run chmod a-w" >&2; exit 2; }; \
		echo "Reusing existing immutable launch manifest; the acceptance preflight will validate it"; \
		exit 0; \
	fi; \
	state_dir="$(ANVA_ACCEPTANCE_STATE_DIR)"; \
	test "$$(id -u)" -ne 0 || { echo "Launch manifest generation must run as a non-root host user" >&2; exit 2; }; \
	test -d "$$state_dir" && test ! -L "$$state_dir" || { echo "ANVA_ACCEPTANCE_STATE_DIR must be a pre-created private directory" >&2; exit 2; }; \
	test -z "$$(find "$$state_dir" -maxdepth 0 -perm /077 -print -quit)" || { echo "ANVA_ACCEPTANCE_STATE_DIR must not grant group/other permissions (use chmod 0700)" >&2; exit 2; }; \
	test -w "$$(dirname "$$manifest")" || { echo "Launch manifest parent directory must be writable" >&2; exit 2; }; \
	input_dir=$$(mktemp -d "$$state_dir/.launch-manifest-input.XXXXXX"); \
	output_tmp="$$(dirname "$$manifest")/.$$(basename "$$manifest").tmp.$$$$"; \
	cleanup() { rm -f "$$output_tmp"; rm -r "$$input_dir"; }; \
	trap cleanup EXIT HUP INT TERM; \
	$(ACCEPTANCE_COMPOSE) --profile acceptance config --format json > "$$input_dir/resolved-compose.json"; \
	docker image inspect "$(ANVA_IMAGE_REF)" > "$$input_dir/image-inspect.json"; \
	docker run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --user "$$(id -u):$$(id -g)" \
		--mount "type=bind,src=$$input_dir,dst=/acceptance/launch-input,readonly" \
		--entrypoint anva "sha256:$(ANVA_IMAGE_SHA256)" acceptance launch-manifest \
		--resolved-compose /acceptance/launch-input/resolved-compose.json \
		--image-inspect /acceptance/launch-input/image-inspect.json \
		--product-commit "$(ANVA_REVISION)" \
		--product-image-sha256 "$(ANVA_IMAGE_SHA256)" \
		--product-image-reference "$(ANVA_IMAGE_REF)" \
		--build-input-sha256 "$(ANVA_BUILD_INPUT_SHA256)" \
		--launch-manifest-source "$$manifest" > "$$output_tmp"; \
	chmod 0444 "$$output_tmp"; \
	mv "$$output_tmp" "$$manifest"; \
	echo "Generated immutable launch manifest at $$manifest"

acceptance-start: acceptance-launch-manifest
	@test -n "$(ANVA_REVISION)" || { echo "ANVA_REVISION is required"; exit 2; }
	@test -n "$(ANVA_IMAGE_SHA256)" || { echo "ANVA_IMAGE_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_BUILD_INPUT_SHA256)" || { echo "ANVA_BUILD_INPUT_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)" || { echo "ANVA_ACCEPTANCE_LAUNCH_MANIFEST is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_MANIFEST_SHA256)" || { echo "ANVA_ACCEPTANCE_MANIFEST_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_SOURCE_FINGERPRINT)" || { echo "ANVA_ACCEPTANCE_SOURCE_FINGERPRINT is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256)" || { echo "ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_STATE_DIR)" || { echo "ANVA_ACCEPTANCE_STATE_DIR is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_CREDENTIAL_DIR)" || { echo "ANVA_ACCEPTANCE_CREDENTIAL_DIR is required"; exit 2; }
	$(ACCEPTANCE_COMPOSE) up -d --wait api worker mcp
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm --no-deps acceptance-product-start

acceptance-review-request: acceptance-identity-preflight
	@test -n "$(ANVA_REVISION)" || { echo "ANVA_REVISION is required"; exit 2; }
	@test -n "$(ANVA_IMAGE_SHA256)" || { echo "ANVA_IMAGE_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_BUILD_INPUT_SHA256)" || { echo "ANVA_BUILD_INPUT_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)" || { echo "ANVA_ACCEPTANCE_LAUNCH_MANIFEST is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_REVIEWER_TOKEN)" || { echo "ANVA_ACCEPTANCE_REVIEWER_TOKEN is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_HANDOFF_DIR)" || { echo "ANVA_ACCEPTANCE_HANDOFF_DIR is required"; exit 2; }
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm --no-deps acceptance-review-request

acceptance-review-submit: acceptance-identity-preflight
	@test -n "$(ANVA_REVISION)" || { echo "ANVA_REVISION is required"; exit 2; }
	@test -n "$(ANVA_IMAGE_SHA256)" || { echo "ANVA_IMAGE_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_BUILD_INPUT_SHA256)" || { echo "ANVA_BUILD_INPUT_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)" || { echo "ANVA_ACCEPTANCE_LAUNCH_MANIFEST is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_REVIEWER_TOKEN)" || { echo "ANVA_ACCEPTANCE_REVIEWER_TOKEN is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_REVIEW_RESULT_DIR)" || { echo "ANVA_ACCEPTANCE_REVIEW_RESULT_DIR is required"; exit 2; }
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm --no-deps acceptance-review-submit

acceptance-finalize: acceptance-identity-preflight
	@test -n "$(ANVA_REVISION)" || { echo "ANVA_REVISION is required"; exit 2; }
	@test -n "$(ANVA_IMAGE_SHA256)" || { echo "ANVA_IMAGE_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_BUILD_INPUT_SHA256)" || { echo "ANVA_BUILD_INPUT_SHA256 is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)" || { echo "ANVA_ACCEPTANCE_LAUNCH_MANIFEST is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_TOKEN)" || { echo "ANVA_ACCEPTANCE_TOKEN is required"; exit 2; }
	@test -n "$(ANVA_ACCEPTANCE_RESULTS_DIR)" || { echo "ANVA_ACCEPTANCE_RESULTS_DIR is required"; exit 2; }
	$(ACCEPTANCE_COMPOSE) --profile acceptance run --rm --no-deps acceptance-product-finalize

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
