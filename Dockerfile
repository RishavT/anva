# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM ghcr.io/astral-sh/uv:0.8.13@sha256:4de5495181a281bc744845b9579acf7b221d6791f99bcc211b9ec13f417c2853 AS uv

FROM python:3.12-slim-trixie@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17 AS base

ARG SOURCE_DATE_EPOCH=1756684800
ARG DEBIAN_SNAPSHOT=20260827T000000Z
ARG OPENSSL_DEBIAN_VERSION=3.5.7-1~deb13u2

RUN printf '%s\n' \
       "deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" \
       "deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ trixie-security main" \
       > /etc/apt/sources.list.d/debian.sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && for package in libssl3t64 openssl openssl-provider-legacy; do \
         apt-cache madison "${package}" | awk '{print $3}' \
           | grep --fixed-strings --line-regexp "${OPENSSL_DEBIAN_VERSION}"; \
       done \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       "libssl3t64=${OPENSSL_DEBIAN_VERSION}" \
       "openssl=${OPENSSL_DEBIAN_VERSION}" \
       "openssl-provider-legacy=${OPENSSL_DEBIAN_VERSION}" \
    && for package in libssl3t64 openssl openssl-provider-legacy; do \
         test "$(dpkg-query -W -f='${Version}' "${package}")" = "${OPENSSL_DEBIAN_VERSION}"; \
       done \
    && rm -rf /var/lib/apt/lists/* \
       /var/cache/ldconfig/aux-cache \
       /var/log/apt/history.log \
       /var/log/apt/term.log \
       /var/log/dpkg.log

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_HTTP_RETRIES=10 \
    UV_HTTP_TIMEOUT=60 \
    UV_LINK_MODE=copy \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    PATH="/app/.venv/bin:${PATH}"

RUN groupadd --gid 10001 anva \
    && useradd --uid 10001 --gid anva --create-home --home-dir /home/anva anva

WORKDIR /app
COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

FROM base AS release-builder
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-default-groups --group release

FROM release-builder AS wheel-builder
COPY src ./src
COPY contracts ./contracts
COPY packages/anva-skills ./packages/anva-skills
RUN --mount=type=cache,target=/root/.cache/uv \
    uv build --python /app/.venv/bin/python --no-build-isolation --offline \
    --wheel --out-dir /dist

FROM base AS runtime
ARG ANVA_VERSION=0.1.6
ARG ANVA_REVISION=unknown
ARG ANVA_BUILD_INPUT_SHA256=0000000000000000000000000000000000000000000000000000000000000000
ARG ANVA_SOURCE=https://github.com/rishavt/anva
COPY --from=wheel-builder /dist /dist
RUN UV_COMPILE_BYTECODE=false uv pip install --no-cache --no-deps /dist/*.whl \
    && dist_info="$(dirname "$(find /app/.venv/lib/python3.12/site-packages \
       -path '*/anva-*.dist-info/uv_cache.json' -print -quit)")" \
    && test -n "${dist_info}" \
    && rm "${dist_info}/uv_cache.json" \
    && sed -i '\|/uv_cache\.json,|d' "${dist_info}/RECORD" \
    && python -m anva.manage collectstatic --noinput \
    && ANVA_BUILD_REVISION="${ANVA_REVISION}" ANVA_BUILD_INPUT_SHA256="${ANVA_BUILD_INPUT_SHA256}" \
       python -c 'import json, os; from pathlib import Path; from anva.acceptance.provenance import package_sha256; root = Path(__import__("anva").__file__).resolve().parent; output = Path("/app/anva-build-provenance.json"); output.write_text(json.dumps({"schema_version": 1, "product_commit": os.environ["ANVA_BUILD_REVISION"], "build_input_sha256": os.environ["ANVA_BUILD_INPUT_SHA256"], "package_sha256": package_sha256(root)}, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8"); output.chmod(0o444)' \
    && mkdir -p /app/acceptance/canonical \
    && chmod 01777 /app/acceptance/canonical \
    && chown -R anva:anva /app
USER 10001:10001
LABEL org.opencontainers.image.title="Anva" \
    org.opencontainers.image.version=${ANVA_VERSION} \
    org.opencontainers.image.revision=${ANVA_REVISION} \
    org.opencontainers.image.source=${ANVA_SOURCE} \
    org.opencontainers.image.licenses="LicenseRef-Proprietary"
CMD ["gunicorn", "anva.config.wsgi:application", "--bind=0.0.0.0:8000", "--access-logfile=/dev/null", "--error-logfile=-"]

FROM base AS test
USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       make=4.4.1-2 \
    && rm -rf /var/lib/apt/lists/* \
       /var/cache/ldconfig/aux-cache \
       /var/log/apt/history.log \
       /var/log/apt/term.log \
       /var/log/dpkg.log
COPY src ./src
COPY contracts ./contracts
COPY packages/anva-skills ./packages/anva-skills
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen
COPY tests ./tests
RUN mkdir -p /app/staticfiles \
    && chown -R anva:anva /app
USER 10001:10001
CMD ["pytest"]

FROM test AS browser-test
USER root
RUN apt-get update \
    && apt-get install --yes --no-install-recommends chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001
CMD ["pytest", "-m", "browser"]
