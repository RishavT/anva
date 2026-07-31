# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.8.13 AS uv

FROM python:3.12.11-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_HTTP_RETRIES=10 \
    UV_HTTP_TIMEOUT=60 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:${PATH}"

RUN groupadd --gid 10001 anva \
    && useradd --uid 10001 --gid anva --create-home --home-dir /home/anva anva

WORKDIR /app
COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

FROM base AS wheel-builder
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv build --wheel --out-dir /dist

FROM base AS runtime
COPY --from=wheel-builder /dist /dist
COPY packages/anva-skills ./packages/anva-skills
RUN uv pip install --no-deps /dist/*.whl \
    && python -m anva.manage collectstatic --noinput \
    && chown -R anva:anva /app
USER anva
CMD ["gunicorn", "anva.config.wsgi:application", "--bind=0.0.0.0:8000", "--access-logfile=-", "--error-logfile=-"]

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
