"""Protocol types + capability-card validation tests."""

from __future__ import annotations

import pytest

from liminal.protocol import (
    ActivationMode,
    CapabilityCard,
    CardValidationError,
    Context,
    Handler,
    ToolResult,
    ToolSpec,
    validate_card,
)


def test_tool_spec_defaults_object_schema() -> None:
    spec = ToolSpec(name="ping", description="hi")
    assert spec.input_schema == {"type": "object", "properties": {}}


def test_tool_result_text_helper() -> None:
    r = ToolResult.text("ok")
    assert r.is_error is False
    assert r.content == [{"type": "text", "text": "ok"}]


def test_tool_result_failure_carries_error() -> None:
    r = ToolResult.failure("nope")
    assert r.is_error is True
    assert r.error == "nope"


def test_validate_card_happy_path() -> None:
    card = validate_card(
        {
            "handler": "slack",
            "description": "x",
            "tools": [{"name": "send", "description": "send a thing"}],
            "activation": "always",
            "credential_keys": ["SLACK_TOKEN"],
            "labels": {"tier": "core"},
        }
    )
    assert isinstance(card, CapabilityCard)
    assert card.activation == ActivationMode.ALWAYS
    assert card.credential_keys == ["SLACK_TOKEN"]


def test_validate_card_defaults_activation_to_always() -> None:
    card = validate_card({"handler": "x", "description": "x"})
    assert card.activation == ActivationMode.ALWAYS


def test_validate_card_accepts_on_demand() -> None:
    card = validate_card(
        {"handler": "x", "description": "x", "activation": "on_demand"}
    )
    assert card.activation == ActivationMode.ON_DEMAND


def test_validate_card_rejects_unknown_activation() -> None:
    with pytest.raises(CardValidationError):
        validate_card({"handler": "x", "description": "x", "activation": "now-please"})


def test_validate_card_requires_handler_and_description() -> None:
    with pytest.raises(CardValidationError):
        validate_card({"handler": "x"})
    with pytest.raises(CardValidationError):
        validate_card({"description": "x"})


def test_context_carries_credentials() -> None:
    ctx = Context(
        identity="rook",
        agent_name="rook-primus",
        credentials={"SLACK_TOKEN": "xoxb-..."},
    )
    assert ctx.credentials["SLACK_TOKEN"].startswith("xoxb-")
    assert ctx.extra == {}


def test_handler_protocol_runtime_check() -> None:
    class Concrete:
        def tools(self):
            return []

        def capability_card(self):
            return {"handler": "x", "description": "x"}

        async def dispatch(self, name, payload, ctx):
            return ToolResult.text("ok")

    class NotHandler:
        pass

    assert isinstance(Concrete(), Handler)
    assert not isinstance(NotHandler(), Handler)
