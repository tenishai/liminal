"""liminal#85 — the tests must import the checkout they are standing in.

`import liminal` resolves through whatever is INSTALLED, and the dev venv has
liminal installed editable against the canonical checkout. Without
`pythonpath = ["src"]` in pyproject.toml, `pytest` run from a git worktree at a
PR head tests **main**, not the PR — and it looks like a normal green run. That
produced a false "their PRs are broken" report (#83/#84 were green in CI
throughout), and Prudence hit it reviewing #81.

TWO GUARDS SHIP HERE, AND THEY COVER DIFFERENT THINGS. Say which is which,
because an earlier draft of this docstring did not and Constance caught it: it
claimed both behavioural assertions had been "thrown away" while the file went
on to ship one of them.

  test_pyproject_still_sets_pythonpath   — a CONFIG assertion. Catches deletion
      of the ini setting, from anywhere. This is the one that actually fires in
      normal use, and it is the realistic regression.

  test_liminal_imports_from_this_checkout — the BEHAVIOURAL assertion. It is
      the property that matters, and it is HOLLOW WHEN RUN FROM THE CANONICAL
      CHECKOUT: the editable install points at that same tree and adds that same
      path, so correct and incorrect configurations are indistinguishable from
      here. Teeth-checked — it stays green with `pythonpath` removed. It has
      teeth only inside a worktree, which is where the bug bit us and the one
      place nobody runs the suite deliberately.

What was actually discarded was not either assertion but the BELIEF that the
behavioural one alone is sufficient. It is kept because it costs nothing and is
the only thing that would catch this in a worktree; it is documented as
conditional rather than presented as proof. Proving the behaviour deliberately
needs a real worktree, and that reproduction lives in the PR body.
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
