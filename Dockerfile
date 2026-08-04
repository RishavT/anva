# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM ghcr.io/astral-sh/uv:0.8.13@sha256:4de5495181a281bc744845b9579acf7b221d6791f99bcc211b9ec13f417c2853 AS uv

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS base

ARG SOURCE_DATE_EPOCH=1756684800

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
COPY packages/anva-skills ./packages/anva-skills
RUN --mount=type=cache,target=/root/.cache/uv \
    uv build --python /app/.venv/bin/python --no-build-isolation --offline \
    --wheel --out-dir /dist

FROM base AS runtime
ARG ANVA_VERSION=0.1.0
ARG ANVA_REVISION=unknown
ARG ANVA_SOURCE=https://github.com/rishavt/anva
COPY --from=wheel-builder /dist /dist
RUN uv pip install --no-deps /dist/*.whl \
    && python -m anva.manage collectstatic --noinput \
    && chown -R anva:anva /app
USER anva
LABEL org.opencontainers.image.title="Anva" \
    org.opencontainers.image.version=${ANVA_VERSION} \
    org.opencontainers.image.revision=${ANVA_REVISION} \
    org.opencontainers.image.source=${ANVA_SOURCE} \
    org.opencontainers.image.licenses="LicenseRef-Proprietary"
CMD ["gunicorn", "anva.config.wsgi:application", "--bind=0.0.0.0:8000", "--access-logfile=/dev/null", "--error-logfile=-"]

FROM base AS test
COPY src ./src
COPY packages/anva-skills ./packages/anva-skills
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen
COPY tests ./tests
RUN mkdir -p /app/staticfiles \
    && chown -R anva:anva /app
USER anva
CMD ["pytest"]

FROM test AS browser-test
USER root
RUN apt-get update \
    && apt-get install --yes --no-install-recommends chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*
USER anva
CMD ["pytest", "-m", "browser"]
