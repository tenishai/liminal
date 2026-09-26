"""#95 — pyproject's version must not fall behind the release tags.

v0.2.0 was tagged by hand on the rename commit (#65) without bumping
`version` in pyproject.toml, so every install from main or from the tag
reported itself as 0.1.0, which a consumer pinning `liminal>=0.2` would reject.
There is no release workflow; tags are cut manually. This check fails when a
`v*` tag reachable from HEAD is newer than pyproject's version.

It needs tags. CI's shallow checkout has none, so there it skips; it bites in
any full clone, which is where tags are cut.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
_RELEASE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _parse(v: str) -> tuple[int, int, int]:
    m = _RELEASE.match("v" + v)
    assert m, f"not a plain X.Y.Z version: {v!r}"
    return (int(m[1]), int(m[2]), int(m[3]))


def _reachable_release_tags() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "tag", "--merged", "HEAD", "--list", "v*"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"git tags unavailable: {exc}")
    return [t for t in out.split() if _RELEASE.match(t)]


def test_pyproject_version_is_not_behind_the_latest_tag() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    tags = _reachable_release_tags()
    if not tags:
        pytest.skip("no v* tags reachable from HEAD (shallow clone?)")
    latest = max(tags, key=lambda t: _parse(t[1:]))
    assert _parse(version) >= _parse(latest[1:]), (
        f"pyproject.toml says {version}, but {latest} is tagged at or before "
        f"HEAD. Bump `version` before tagging (see AGENTS.md, Releasing)."
    )
