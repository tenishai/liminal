"""Guides that ship inside the wheel, printed by `liminal guide`.

An agent on a machine that has the package but not the repo can still read
what liminal is and which options it has. The markdown lives here, inside the
package, because setuptools ships package data only from inside a package and
the Dockerfile copies only `src/`. `pyproject.toml`'s package-data entry for
`liminal.docs` carries them into the wheel; tests/test_bundled_docs.py fails if
a guide named here is missing from disk or from that entry.
"""

from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).parent

#: Every bundled guide, by the name `liminal guide <name>` accepts, with the
#: one line the listing prints.
GUIDES: dict[str, str] = {
    "welcome": "What liminal is, where it fits, and each option with why you'd pick it.",
}


def guide_path(name: str) -> Path:
    """The file for one guide, or KeyError.

    The name is checked against GUIDES before any path is built, so a CLI
    argument such as `../../etc/passwd` never reaches the filesystem."""
    if name not in GUIDES:
        raise KeyError(name)
    return _DIR / f"{name}.md"


def bundled_guide(name: str) -> str:
    """The markdown text of one guide."""
    return guide_path(name).read_text(encoding="utf-8")
