"""Capability card validation.

Schema per design.md §"Capability cards". The card is documentation —
limenal doesn't enforce `credential_keys`, but it does want the structure
to parse cleanly so v2 on-demand activation can use the fields without
defensive coding everywhere.

`validate_card` is the single entry point. It either returns a parsed
CapabilityCard or raises CardValidationError. Handlers carry the raw
dict; the registry runs validation at discovery time.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ActivationMode(StrEnum):
    ALWAYS = "always"      # v1 default — tool surface is in every list_tools
    ON_DEMAND = "on_demand"  # v2 — activated via limenal__activate after match


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")


class _ToolEntry(_Open):
    name: str
    description: str


class CapabilityCard(_Open):
    handler: str
    description: str
    tools: list[_ToolEntry] = Field(default_factory=list)
    activation: ActivationMode = ActivationMode.ALWAYS
    relevance_signals: list[str] = Field(default_factory=list)
    credential_keys: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    # The scope a sovereign grant must hold (or admin:*) to invoke this
    # handler. None = no scope gate (an open handler). In a sovereign
    # deployment the server derives the handler->scope map from these fields
    # (limenal#26) rather than a hand-authored [scope_map] that can drift from
    # the handler surface.
    required_scope: str | None = None


class CardValidationError(ValueError):
    """Raised when a capability card is structurally invalid."""


def validate_card(raw: dict[str, Any]) -> CapabilityCard:
    """Parse a capability-card dict. Raises CardValidationError on bad input."""
    try:
        return CapabilityCard.model_validate(raw)
    except ValidationError as exc:
        raise CardValidationError(str(exc)) from exc
