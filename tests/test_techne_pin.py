"""The techne pin is stated in three places, and they must agree.

requirements-sources.txt pins the git tag a clean install gets, pyproject.toml's
`memory` extra carries the matching floor, and the Dockerfile's TECHNE_VERSION
is what the image installs (by version and wheel sha256 from an index, or by
version check on a sibling checkout). They drifted once already: the requirements
pin said v0.17.0 while the image took whatever an index offered. One of them
moving without the others is a half-done bump.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _dockerfile_arg(name: str) -> str:
    m = re.search(rf"^ARG {name}=(\S+)$", (ROOT / "Dockerfile").read_text(), re.M)
    assert m, f"no `ARG {name}=` in the Dockerfile"
    return m[1]


def test_requirements_tag_matches_the_dockerfile() -> None:
    m = re.search(r"tenishai/techne\.git@v(\S+)", (ROOT / "requirements-sources.txt").read_text())
    assert m, "no techne git pin in requirements-sources.txt"
    assert m[1] == _dockerfile_arg("TECHNE_VERSION")


def test_memory_floor_matches_the_dockerfile() -> None:
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]
    floors = [re.fullmatch(r"techne>=(\S+)", d) for d in extras["memory"]]
    floors = [f[1] for f in floors if f]
    assert floors == [_dockerfile_arg("TECHNE_VERSION")], extras["memory"]


def test_wheel_hash_is_a_sha256() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", _dockerfile_arg("TECHNE_WHEEL_SHA256"))
