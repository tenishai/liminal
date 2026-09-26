"""#91 — the README's handler example must be written the way shipped handlers are.

`Handler` is a `typing.Protocol`. Conformance is structural, so no shipped
handler subclasses it, and the README sample used to (`class
GreetHandler(Handler)`) — teaching that inheritance is required and giving an
out-of-tree handler a hard dependency on liminal's class identity. These pin
both sides so the example cannot drift from the code again.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _handler_classes(tree: ast.AST) -> list[ast.ClassDef]:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name.endswith("Handler")
    ]


def _base_names(cls: ast.ClassDef) -> set[str]:
    return {ast.unparse(b).rsplit(".", 1)[-1] for b in cls.bases}


def test_no_shipped_handler_subclasses_the_protocol() -> None:
    found = []
    for path in sorted((ROOT / "src" / "liminal" / "handlers").glob("*.py")):
        for cls in _handler_classes(ast.parse(path.read_text())):
            found.append(cls.name)
            assert "Handler" not in _base_names(cls), f"{path.name}: {cls.name}"
    assert found, "no *Handler classes found — did handlers/ move?"


def test_readme_handler_example_does_not_subclass_the_protocol() -> None:
    readme = (ROOT / "README.md").read_text()
    section = readme.split("## Wiring a handler", 1)[1]
    block = section.split("```python", 1)[1].split("```", 1)[0]
    classes = _handler_classes(ast.parse(block))
    assert classes, "no handler class in the README's wiring example"
    for cls in classes:
        assert "Handler" not in _base_names(cls), cls.name
