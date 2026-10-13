"""Static target headers are checked at load against what HTTP will accept
(liminal#141). Before, a name with spaces or a value with CR/LF loaded fine and
the first request failed inside h11 with LocalProtocolError."""

from __future__ import annotations

import pytest

from liminal.target.config import TargetConfigError, TargetSpec


def _spec(headers: dict) -> TargetSpec:
    return TargetSpec(name="t", address="https://x", headers=headers)


@pytest.mark.parametrize("name", [" X-Foo ", "X-Foo ", "Bad Name", "X:Foo", "X\tFoo", "Ünicode", "X(Foo)"])
def test_a_name_http_would_refuse_is_refused_at_load(name):
    with pytest.raises(TargetConfigError, match="not a valid HTTP field name"):
        _spec({name: "v"}).validate()


@pytest.mark.parametrize("value", ["a\r\nX-Injected: 1", "a\nb", "a\rb", "a\0b"])
def test_a_value_with_cr_lf_or_nul_is_refused_at_load(value):
    with pytest.raises(TargetConfigError, match="CR, LF or NUL"):
        _spec({"X-Foo": value}).validate()


@pytest.mark.parametrize("name", ["X-MCP-Readonly", "x_custom", "X.Trace~1", "!#$%&'*+-.^_`|~"])
def test_valid_token_names_load(name):
    _spec({name: "value with spaces is fine"}).validate()


def test_a_padded_reserved_name_is_still_refused():
    # Refused for its padding now, which is still a refusal; it used to be
    # caught only by the strip-then-compare reserved check.
    with pytest.raises(TargetConfigError):
        _spec({" Authorization": "Bearer x"}).validate()


BAD_NAMES = [" X-Foo ", "X-Foo ", "Bad Name", "X:Foo", "X\tFoo", "Ünicode", "X(Foo)"]
BAD_VALUES = ["a\r\nX-Injected: 1", "a\nb", "a\rb", "a\0b"]


@pytest.mark.parametrize("name, value", [(n, "v") for n in BAD_NAMES] + [("X-Foo", v) for v in BAD_VALUES])
def test_everything_refused_at_load_was_already_refused_on_the_wire(name, value):
    """The CHANGELOG says no working config is refused by this check. That
    holds while h11, httpx's HTTP/1.1 layer, refuses each of these too."""
    import h11

    with pytest.raises(h11.LocalProtocolError):
        h11.Request(method="GET", target="/", headers=[("Host", "x"), (name.encode(), value.encode())])
