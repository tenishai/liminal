"""The guides ship in the wheel, and `liminal guide` reads them.

A guide missing from pyproject's package-data still reads fine from a checkout,
so a developer sees it work while every installed user gets an error. These
tests compare the guide list with the package-data glob and the files on disk,
which catches that in either direction.
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path

import pytest

from liminal import cli
from liminal.docs import GUIDES, bundled_guide, guide_path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "src" / "liminal" / "docs"


def _pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def _package_data_globs() -> list[str]:
    data = _pyproject().get("tool", {}).get("setuptools", {}).get("package-data", {})
    return list(data.get("liminal.docs", []))


def test_package_data_names_the_docs_package() -> None:
    # Every check below passes vacuously if this list is empty.
    assert _package_data_globs(), "no package-data for liminal.docs: the guides stopped shipping"


@pytest.mark.parametrize("name", sorted(GUIDES))
def test_every_guide_is_a_real_file_in_the_wheel(name: str) -> None:
    path = guide_path(name)
    assert path.is_file(), f"{name}: {path} does not exist"
    assert path.parent == DOCS
    assert any(fnmatch.fnmatch(path.name, g) for g in _package_data_globs()), (
        f"{path.name} does not match package-data {_package_data_globs()}"
    )
    assert len(bundled_guide(name)) > 500, f"{name} is implausibly short"


def test_every_shipped_markdown_file_is_a_listed_guide() -> None:
    # A file the wheel carries but GUIDES does not name can never be printed.
    shipped = {p.stem for p in DOCS.iterdir() if any(fnmatch.fnmatch(p.name, g) for g in _package_data_globs())}
    assert shipped == set(GUIDES), f"shipped {sorted(shipped)} vs listed {sorted(GUIDES)}"


@pytest.mark.parametrize("hostile", ["../../../etc/passwd", "/etc/passwd", "..", "", "WELCOME"])
def test_a_guide_name_cannot_escape_the_docs_directory(hostile: str) -> None:
    with pytest.raises(KeyError):
        guide_path(hostile)


def test_guide_with_no_name_lists_every_guide(capsys) -> None:
    assert cli.main(["guide"]) == 0
    out = capsys.readouterr().out
    for name, line in GUIDES.items():
        assert name in out
        assert line in out


def test_guide_prints_the_file_verbatim(capsys) -> None:
    assert cli.main(["guide", "welcome"]) == 0
    assert capsys.readouterr().out == bundled_guide("welcome")


def test_an_unknown_guide_fails_and_names_the_valid_ones(capsys) -> None:
    assert cli.main(["guide", "no-such-guide"]) == 2
    err = capsys.readouterr().err
    assert "no-such-guide" in err
    for name in GUIDES:
        assert name in err


def test_welcome_covers_every_built_in_handler() -> None:
    # A handler added to the entry points without a line in the guide fails here.
    handlers = _pyproject()["project"]["entry-points"]["liminal.handlers"]
    text = bundled_guide("welcome")
    missing = [h for h in handlers if f"| `{h}` |" not in text]
    assert not missing, f"welcome.md has no handler row for {missing}"


def test_welcome_covers_every_extra() -> None:
    extras = _pyproject()["project"]["optional-dependencies"]
    text = bundled_guide("welcome")
    missing = [e for e in extras if f"tenish-liminal[{e}]" not in text]
    assert not missing, f"welcome.md does not describe extras {missing}"
