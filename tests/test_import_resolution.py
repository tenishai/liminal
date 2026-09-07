"""liminal#85 — the tests must import the checkout they are standing in.

`import liminal` resolves through whatever is INSTALLED, and the dev venv has
liminal installed editable against the canonical checkout. Without
`pythonpath = ["src"]` in pyproject.toml, `pytest` run from a git worktree at a
PR head tests **main**, not the PR — and it looks like a normal green run. That
produced a false "their PRs are broken" report (#83/#84 were green in CI
throughout), and Prudence hit it reviewing #81.

WHY THE OBVIOUS TESTS DO NOT WORK, since both were written and thrown away:

Asserting `liminal.__file__` is inside this checkout, and asserting this
checkout's `src` is on `sys.path`, BOTH pass with the setting deleted whenever
you run from the canonical checkout — the editable install points at that same
tree and adds that same path, so the correct and incorrect configurations are
indistinguishable from here. Teeth-checked: both stayed green with `pythonpath`
removed. They fail only inside a worktree, which is the one place nobody runs
the suite deliberately.

So the guard below is a CONFIG assertion, not a behavioural one, and it is
labelled as such rather than dressed up as more. It catches deletion of the
setting, which is the realistic regression. Proving the behaviour needs a real
worktree; that lives in the PR body as a manual check.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import liminal


def test_pyproject_still_sets_pythonpath() -> None:
    """A config assertion. See the module docstring for why it is not more."""
    root = Path(__file__).resolve().parent.parent
    with (root / "pyproject.toml").open("rb") as fh:
        cfg = tomllib.load(fh)
    pythonpath = cfg["tool"]["pytest"]["ini_options"].get("pythonpath")
    assert pythonpath == ["src"], (
        f"[tool.pytest.ini_options] pythonpath is {pythonpath!r}, expected "
        '["src"]. Without it, a pytest run from a git worktree imports '
        "liminal from whatever is installed — a DIFFERENT checkout — and "
        "silently tests the wrong tree (liminal#85)."
    )


def test_liminal_imports_from_this_checkout() -> None:
    """The property that matters. Green either way in the canonical checkout;
    it is the worktree case this catches, and that is where it bit us."""
    here = Path(__file__).resolve().parent.parent
    resolved = Path(liminal.__file__).resolve()
    assert resolved.is_relative_to(here), (
        f"tests are importing liminal from {resolved}, which is OUTSIDE this "
        f"checkout ({here}). An editable install is shadowing the tree under "
        "test — see liminal#85."
    )
    assert str(here / "src") in [p for p in sys.path if p]
