# syntax=docker/dockerfile:1.7
# Multi-stage build for liminal MCP gateway.

# ----- techne: a sibling checkout, or a package index -------------------------
# Two ways in, same image either way:
#   --build-context techne=../techne                       (compose, dev: unchanged)
#   --build-arg EXTRA_INDEX_URL=https://<index>/simple/    (a package index)
#     [--secret id=ar_token,env=AR_TOKEN]  for a private Artifact Registry index
#     (a BuildKit secret: never in the image or the build log; the deploy
#     platform's generated CI passes it this way). --build-arg AR_TOKEN=… still
#     works for a local build, but lands in the build log; the
#     token Gojira's generated CI passes to every build (2026-09-30).
# techne itself is fetched from that index ALONE, then installed as a file, so
# only its dependencies come from PyPI. The name `techne` on PyPI belongs to
# someone else (0.0.2 as of 2026-10-01); with the index as an *extra* index,
# pip would take whichever index offers the highest version, and a later
# release there would land in this image.
# From the index, techne is pinned to one wheel by version AND sha256
# (TECHNE_VERSION, TECHNE_WHEEL_SHA256). Anything with write access to the
# index can publish a file under a version number, so the version alone names
# nothing: on 2026-10-02 the tenish index's techne 0.18.0 turned out to be a
# build from before the v0.18.0 tag. When this step runs, a wheel whose hash
# does not match stops the build. A warm build cache can skip the step and
# reuse the layer an earlier run built, so the check runs on a cold build or
# after the args change. Moving to a new techne means changing both args
# together, to a wheel built from that version's tag, along with
# requirements-sources.txt and pyproject.toml's `memory` floor.
# tests/test_techne_pin.py fails when the version, the requirements pin and the
# floor disagree; it checks only that the hash is a sha256, so a stale hash is
# caught when the image is built, not by the tests.
# The arg is not called PIP_EXTRA_INDEX_URL on purpose: pip reads that name
# from the environment, and a build ARG is environment for every later RUN of
# the stage, so the second install would stop to ask for a password.
# `--build-context techne=` overrides the empty stage below by name. Without
# it the stage is empty, the copy yields nothing, and the install falls
# through to the index. Neither given: the build stops and says so.
FROM scratch AS techne

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

# See CABAL-DECISIONS D-008/D-012 for why techne is a build input. When it
# lands on PyPI, drop the techne stage and the install branch below and add a
# `tenish-techne>=` pin at the current TECHNE_VERSION to pyproject.toml's dependencies.
COPY --from=techne / /build/techne
ARG EXTRA_INDEX_URL=""
ARG AR_TOKEN=""
# techne v0.18.2 (tag at 96a030d), the py3-none-any wheel. From 0.18.2 the
# distribution is tenish-techne; the import package is still techne.
ARG TECHNE_VERSION=0.18.2
ARG TECHNE_WHEEL_SHA256=43e96409b99a7d9e4bf5f075226b87464db5830e9bdb8323ab4f7f3675c29e51
# A sibling checkout must report TECHNE_VERSION too. That catches a checkout of
# another release; it cannot catch techne's main between releases, which reports
# the last released version. scripts/check-techne-sibling.sh compares commits.
# TECHNE_ANY_VERSION=1 skips this check, for building against whatever the
# sibling has checked out.
ARG TECHNE_ANY_VERSION=""

# Layer-cache: copy pyproject.toml first, install all deps (and a stub package
# so the build system is satisfied), then copy the real source last so a
# code-only change doesn't bust the dependency install layer.
COPY pyproject.toml README.md LICENSE ./
RUN --mount=type=secret,id=ar_token \
    python3 -m venv /venv \
 && if [ -f /build/techne/pyproject.toml ]; then \
      sib="$(sed -n 's/^version = "\(.*\)"/\1/p' /build/techne/pyproject.toml | head -1)"; \
      if [ "$sib" != "$TECHNE_VERSION" ] && [ "$TECHNE_ANY_VERSION" != "1" ]; then \
        echo "techne: the sibling checkout is $sib, but TECHNE_VERSION pins $TECHNE_VERSION. Check out v$TECHNE_VERSION, or pass --build-arg TECHNE_ANY_VERSION=1." >&2; exit 1; \
      fi \
      && /venv/bin/pip install --no-cache-dir /build/techne; \
    elif [ -n "$EXTRA_INDEX_URL" ]; then \
      if [ -r /run/secrets/ar_token ] && [ -s /run/secrets/ar_token ]; then AR_TOKEN="$(cat /run/secrets/ar_token)"; fi; \
      if [ -n "$AR_TOKEN" ]; then EXTRA_INDEX_URL="$(echo "$EXTRA_INDEX_URL" | sed "s#://#://oauth2accesstoken:${AR_TOKEN}@#")"; unset AR_TOKEN; fi; \
      /venv/bin/pip download --no-cache-dir --no-deps --only-binary :all: --index-url "$EXTRA_INDEX_URL" -d /tmp/techne-dist "tenish-techne==${TECHNE_VERSION}" \
      && echo "${TECHNE_WHEEL_SHA256}  /tmp/techne-dist/tenish_techne-${TECHNE_VERSION}-py3-none-any.whl" | sha256sum -c - \
      && /venv/bin/pip install --no-cache-dir /tmp/techne-dist/tenish_techne-${TECHNE_VERSION}-py3-none-any.whl \
      && rm -rf /tmp/techne-dist; \
    else \
      echo "techne: pass --build-context techne=../techne or --build-arg EXTRA_INDEX_URL=… (see the techne stage)" >&2; exit 1; \
    fi \
 && mkdir -p src/liminal && touch src/liminal/__init__.py \
 && /venv/bin/pip install --no-cache-dir . \
 && rm -rf src build

COPY src ./src
# The stub install above leaves setuptools' build/ tree behind unless it is removed
# with src, and a stale build/ makes this install ship the empty stub __init__.py
# (tenishai/liminal#126). The import check fails the build if that ever recurs.
RUN /venv/bin/pip install --no-cache-dir --no-deps . \
 && /venv/bin/python -c "import liminal, liminal.server; v = liminal.__version__; assert v != '0.0.0+unknown', v; print('liminal', v)"

# ----- Runtime stage --------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/venv/bin:$PATH" \
    VIRTUAL_ENV="/venv"

# The upgrade pass pulls base-image packages (libc6, zlib1g, libpcre2, ...)
# up to current Debian security revisions WHEN THIS LAYER REBUILDS. Docker
# caches a RUN step by its parent layer and its text, not by what it downloads,
# so a plain rebuild on a warm builder reuses the last upgrade and goes stale
# exactly like the base layer. APT_REFRESH breaks that: pass a new value, e.g.
# `--build-arg APT_REFRESH=$(date +%F)`, and the upgrade runs again.
ARG APT_REFRESH=unset
RUN echo "apt refresh: ${APT_REFRESH}" && apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
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
