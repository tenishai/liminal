# syntax=docker/dockerfile:1.7
# Multi-stage build for liminal MCP gateway.

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

# techne is brought in via BuildKit `--build-context techne=../techne`
# (set by docker-compose.yml's additional_contexts). See CABAL-DECISIONS D-008/D-012.
# When techne lands on PyPI, drop both COPY+install lines and add a `techne>=0.6.0`
# pin to pyproject.toml's dependencies.
COPY --from=techne / /build/techne

# Layer-cache: copy pyproject.toml first, install all deps (and a stub package
# so the build system is satisfied), then copy the real source last so a
# code-only change doesn't bust the dependency install layer.
COPY pyproject.toml README.md LICENSE ./
RUN python3 -m venv /venv \
 && /venv/bin/pip install --no-cache-dir /build/techne \
 && mkdir -p src/liminal && touch src/liminal/__init__.py \
 && /venv/bin/pip install --no-cache-dir . \
 && rm -rf src

COPY src ./src
RUN /venv/bin/pip install --no-cache-dir --no-deps .

# ----- Runtime stage --------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/venv/bin:$PATH" \
    VIRTUAL_ENV="/venv"

# The upgrade pass pulls base-image packages (libc6, zlib1g, libpcre2, ...)
# up to current Debian security revisions even when the builder's cached
# python:3.12-slim base layer is weeks stale — published CVE fixes
# otherwise never reach the image no matter how often it is rebuilt.
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Non-root user. UID 10002 distinct from cabal's 10001 so both can run on
# the same host without UID collisions on shared bind-mounts.
RUN groupadd --gid 10002 liminal && \
    useradd --uid 10002 --gid liminal --home-dir /home/liminal --create-home liminal

COPY --from=build /venv /venv

WORKDIR /app

USER liminal

EXPOSE 9100

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9100/healthz || exit 1

# --jwks-url and --cabal-url are injected by docker-compose via `command:`.
CMD ["liminal", "serve", "--host", "0.0.0.0", "--port", "9100"]
