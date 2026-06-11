"""Registry discovery + explicit-registration tests."""

from __future__ import annotations

import pytest

from limenal.protocol import Context, Handler, ToolResult, ToolSpec
from limenal.registry import HandlerRecord, Registry
from limenal.registry.discover import (
    DiscoveryError,
    discover_handlers,
    register_explicit,
)


class _GoodHandler:
    def tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="ping", description="pong")]

    def capability_card(self) -> dict:
        return {
            "handler": "good",
            "description": "a working test handler",
            "tools": [{"name": "ping", "description": "pong"}],
        }

    async def dispatch(self, name, payload, ctx):
        return ToolResult.text("pong")


class _BadCardHandler:
    def tools(self):
        return []

    def capability_card(self):
        return {"handler": "bad", "activation": "INVALID"}

    async def dispatch(self, name, payload, ctx):
        return ToolResult.text("nope")


def test_registry_get_returns_none_for_unknown() -> None:
    r = Registry()
    assert r.get("ghost") is None


def test_register_explicit_validates_card() -> None:
    r = Registry()
    register_explicit(r, "good", _GoodHandler(), source="test")
    assert r.get("good") is not None
    assert r.names() == ["good"]


def test_register_explicit_rejects_bad_card() -> None:
    r = Registry()
    with pytest.raises(DiscoveryError):
        register_explicit(r, "bad", _BadCardHandler())


def test_registry_iter_yields_records() -> None:
    r = Registry()
    register_explicit(r, "a", _GoodHandler(), source="t")
    register_explicit(r, "b", _GoodHandler(), source="t")
    records = list(r)
    assert len(records) == 2
    assert {rec.name for rec in records} == {"a", "b"}


def test_registry_duplicate_register_last_wins(caplog) -> None:
    r = Registry()
    first = _GoodHandler()
    second = _GoodHandler()
    register_explicit(r, "dup", first, source="first")
    register_explicit(r, "dup", second, source="second")
    assert r.get("dup").handler is second


def test_discover_handlers_includes_scratchpad() -> None:
    """The scratchpad handler is declared in pyproject's entry-points;
    pip install -e . registers it so discovery finds it."""
    registry = discover_handlers()
    record = registry.get("scratchpad")
    assert record is not None
    assert record.card.handler == "scratchpad"
    assert any(t.name == "set" for t in record.card.tools)


def test_discover_handlers_only_filter() -> None:
    registry = discover_handlers(only=["scratchpad"])
    assert "scratchpad" in registry.names()
    # only=[scratchpad] should not pull anything else even when it exists
    for name in registry.names():
        assert name == "scratchpad"


def test_discover_handlers_only_filter_drops_unknown() -> None:
    registry = discover_handlers(only=["does-not-exist"])
    assert len(registry) == 0
