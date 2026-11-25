# Releasing liminal

A liminal release is a version bump in a pull request, a tag on the merge commit, and a
GitHub release. Everything is done by hand: there is no release workflow, and nothing in CI
reacts to a tag. This file records what the last releases did, so the next one does not rely
on memory. It is short on purpose; `AGENTS.md` has the one-paragraph rule.

Release order across the suite: techne first, then liminal, then cabal. liminal's `memory`
extra needs techne, and cabal's `mcp` and `full` extras need liminal.

## When to cut a release

Cut one when it has a reason to exist: name who will install it and how. Don't cut one
because a fix just merged; a fix on main waits for the next release with a reason.

Before you tag, make sure the release will not need a patch the same session has to cut.
Resolve the downstream version set against the index, with every extra, using the candidate
version:

```
echo 'tenish-liminal[<every extra in pyproject.toml>]==X.Y.Z' > release.in   # plus the downstream set's other pins
uv pip compile --index https://pypi.tenish.ai/simple release.in
```

It must resolve with no conflict. Then install the result where it is going (the environment or
image that will run it) and run it. The index asks for a token during the limited
release.

## The release PR

One pull request, from a branch, titled `release: liminal X.Y.Z`. It carries:

- `version` in `pyproject.toml`. The build backend is setuptools; `liminal.__version__`
  reads the installed package's metadata, so this is the only place the number lives.
- `CHANGELOG.md`: rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD` (past blocks, for
  example `## [0.10.0] — 2026-11-19`) and put a fresh empty `## [Unreleased]` above it. Add an
  `### Upgrading` section for anything an existing install must act on.
- Docs that name the version. `ARCHITECTURE.md` has a `STATE:` line that names the version, as `vX.Y.Z
  (pyproject)`, and lists each release's changes. Grep for the previous version and
  fix what you find.
- `ARCHITECTURE.md` anchors `pyproject.toml` by blob sha, so the bump makes it stale. Run `python3 scripts/check_arch_cards.py`, update the
  anchor, and expect `all architecture cards fresh`.

Check `git log --oneline v<previous>..HEAD` against `[Unreleased]` and add whatever is
missing. Two pins move with techne, not with this release: if you change the `tenish-techne`
floor in the `memory` extra, move `requirements-sources.txt` and the Dockerfile's
`TECHNE_VERSION` and `TECHNE_WHEEL_SHA256` with it. `tests/test_techne_pin.py` fails when they
disagree.

Run the full suite before you open the PR. The PR needs the `ci` and `dco` checks, one
review, and a squash merge. `pyproject.toml` is code, so Prudence reviews it through the
code-owner rule, as for any code change.
Prudence is the project's AI code reviewer, the code owner for everything but docs.

## Tag the merge commit

A maintainer tags the squash commit on main, annotated, with the same number as `pyproject.toml`:

```
git checkout main && git pull
git tag -a vX.Y.Z -m "liminal X.Y.Z"
git push origin vX.Y.Z
```

The rulesets allow only maintainers to create `v*` tags and forbid moving or deleting one.
A bad release is followed by a new version, never a retag. `tests/test_version_tags.py` fails
when a reachable `v*` tag is newer than `pyproject.toml` (v0.2.0 shipped reporting 0.1.0,
#95). It needs tags, so it skips in CI's shallow checkout; run it in a full clone.

## Publish

Two things are published by hand, after the tag:

1. **The GitHub release**, named `liminal X.Y.Z`, with the body taken from the CHANGELOG
   section including `### Upgrading`. The releases for v0.9.0 through v0.10.0 exist and carry
   no assets.
2. **The wheel on `https://pypi.tenish.ai/simple`.** A maintainer builds the wheel from the tag twice, with
   `SOURCE_DATE_EPOCH` set to the tag commit's time and checks that the hashes match; publishes it with the
   index's publish script (maintainers only); checks the sha256 in the
   index metadata; and attaches the wheel and a `SHA256SUMS` file to the GitHub release. The index
   is immutable, so a mistake is fixed by a new version.

Whether each liminal version since 0.7.1 is on the index is not recorded in this repo. The
GitHub releases show no wheels for them; check the index before you tell anyone to
install one.

## After

- `[Unreleased]` is already fresh from the PR.
- Tell the cabal side: its `requirements-sources.txt` and Dockerfile pin liminal, and its `mcp`
  extra names `tenish-liminal>=0.4`. Bumping those is a cabal pull request, after this one.
- Version sets that pin exact component versions move in their own pull requests, after the
  wheel is on the index.

## Not yet

No tag-triggered release workflow, scan gate or SBOM exists here, unlike kobo's.
