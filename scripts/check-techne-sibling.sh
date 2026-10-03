#!/usr/bin/env bash
# Is ../techne the techne this Dockerfile pins? Run it before a sibling-checkout
# build (`docker build --build-context techne=../techne .`). Copied from
# tenishai/cabal scripts/check-techne-sibling.sh on 2026-10-03; cabal's
# `make build` / `make up` run their copy, and cabal's compose builds this image.
#
# WHY OUTSIDE DOCKER: the build cannot answer this. techne's .dockerignore drops
# .git, so the build context has no commit to compare, and the version string
# names nothing on its own: techne's main reports the released version until the
# next release is cut (2026-10-02, main said 0.18.0 one commit past the v0.18.0
# tag). The Dockerfile keeps a version-string check as a backstop for direct
# `docker compose` runs; this is the check that compares commits.
#
# The pin is the Dockerfile's TECHNE_VERSION, read from there so there is one
# place to change. TECHNE_ANY=1 skips the check, for building against whatever
# ../techne has checked out (developing techne and liminal together).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
sibling="${TECHNE_DIR:-$here/../techne}"

if [ "${TECHNE_ANY:-}" = "1" ]; then
  echo "techne: TECHNE_ANY=1, not checking $sibling against the pin" >&2
  exit 0
fi

# The tag lookup below swallows git's errors (`|| true`), so a missing git, or
# a git that refuses the checkout, would surface as "has no tag". Both are
# caught first and reported as what they are.
if ! command -v git >/dev/null 2>&1; then
  echo "techne: git is not installed, so $sibling cannot be checked against the pin." >&2
  echo "  Install git, or TECHNE_ANY=1 to build without the check." >&2
  exit 1
fi

version="$(sed -n 's/^ARG TECHNE_VERSION=//p' "$here/Dockerfile")"
if [ -z "$version" ]; then
  echo "techne: no ARG TECHNE_VERSION in $here/Dockerfile" >&2
  exit 1
fi
tag="v$version"

if [ ! -d "$sibling/.git" ] && [ ! -f "$sibling/.git" ]; then
  echo "techne: $sibling is not a git checkout. Clone it at the pinned tag:" >&2
  echo "  git clone --branch $tag https://github.com/tenishai/techne.git $sibling" >&2
  exit 1
fi

# A checkout owned by another uid (a bind mount, as root) trips git's
# safe.directory check; show git's own message rather than misreading it.
if ! err="$(git -C "$sibling" rev-parse --git-dir 2>&1 >/dev/null)"; then
  echo "techne: git cannot read $sibling:" >&2
  echo "  $err" >&2
  exit 1
fi

want="$(git -C "$sibling" rev-parse -q --verify "refs/tags/$tag^{commit}" || true)"
if [ -z "$want" ]; then
  echo "techne: $sibling has no tag $tag. Fetch tags: git -C $sibling fetch --tags" >&2
  exit 1
fi
have="$(git -C "$sibling" rev-parse HEAD)"
if [ "$have" != "$want" ]; then
  echo "techne: $sibling is at ${have:0:7}, but this Dockerfile pins $tag (${want:0:7})." >&2
  echo "  git -C $sibling checkout $tag" >&2
  echo "  or TECHNE_ANY=1 to build against what is checked out." >&2
  exit 1
fi
if [ -n "$(git -C "$sibling" status --porcelain --untracked-files=no)" ]; then
  echo "techne: $sibling is at $tag but has uncommitted changes to tracked files." >&2
  echo "  Commit or stash them, or TECHNE_ANY=1 to build them in." >&2
  exit 1
fi
echo "techne: $sibling is $tag (${want:0:7})"
