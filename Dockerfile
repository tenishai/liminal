# syntax=docker/dockerfile:1.7
# Multi-stage build for limenal MCP gateway.

# ----- Build stage ----------------------------------------------------------
FROM python:3.12-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps for cryptography (cffi); slim image lacks them.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Layer caching: copy only metadata first, install deps, then copy source.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# techne is brought in via BuildKit `--build-context techne=../techne`
# (set by docker-compose.yml's additional_contexts). See CABAL-DECISIONS D-008/D-012.
# When techne lands on PyPI, drop both COPY+install lines and add a `techne>=0.6.0`
# pin to pyproject.toml's dependencies.
COPY --from=techne / /build/techne

RUN python3 -m venv /venv \
 && /venv/bin/pip install --no-cache-dir /build/techne \
 && /venv/bin/pip install --no-cache-dir .

# ----- Runtime stage --------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/venv/bin:$PATH" \
    VIRTUAL_ENV="/venv"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Non-root user. UID 10002 distinct from cabal's 10001 so both can run on
# the same host without UID collisions on shared bind-mounts.
RUN groupadd --gid 10002 limenal && \
    useradd --uid 10002 --gid limenal --home-dir /home/limenal --create-home limenal

COPY --from=build /venv /venv

WORKDIR /app

USER limenal

EXPOSE 9100

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9100/healthz || exit 1

# --jwks-url and --cabal-url are injected by docker-compose via `command:`.
CMD ["limenal", "serve", "--host", "0.0.0.0", "--port", "9100"]
