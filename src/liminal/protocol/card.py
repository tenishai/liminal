"""Capability card validation.

Schema per design.md §"Capability cards". The card is documentation —
liminal doesn't enforce `credential_keys`, but it does want the structure
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
    ON_DEMAND = "on_demand"  # v2 — activated via liminal__activate after match


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")


class _ToolEntry(_Open):
    name: str
    description: str
    # Per-tool required scope (liminal#42). Enforced at tools/call for the
    # specific tool "<handler>.<name>", taking precedence over the handler-level
    # required_scope. Lets a read/write split (memory recall vs commit, files
    # read vs write) be scope-gated without collapsing to one privilege. None =
    # fall back to the handler-level scope (or open if that's None too).
    #
    # FOOTGUN: per-tool wins even when WEAKER than the handler-level scope — a
    # per-tool value can silently DOWNGRADE a tool below its handler's
    # protection (there is no "max of the two"). Use this to REFINE (narrow) a
    # handler scope, never to widen it.
    required_scope: str | None = None
    # Operator-only tool (cabal#233). Enforced at tools/call and filtered from
    # tools/list, independently of required_scope: single-cabal mode needs the
    # verified token's cabal_scope (fallback `scope`) to hold "operator";
    # sovereign mode needs the policy grant to hold it (or admin:*), never the
    # token's own claim; auth-off refuses outright (no verified identity).
    requires_operator: bool = False


class CapabilityCard(_Open):
    handler: str
    description: str
    tools: list[_ToolEntry] = Field(default_factory=list)
    activation: ActivationMode = ActivationMode.ALWAYS
    credential_keys: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    # The scope a sovereign grant must hold (or admin:*) to invoke this
    # handler. None = no scope gate (an open handler). In a sovereign
    # deployment the server derives the handler->scope map from these fields
    # (liminal#26) rather than a hand-authored [scope_map] that can drift from
    # the handler surface.
    #
    # This is DEFENCE-IN-DEPTH atop the operator-authored allowed_handlers
    # gate (which runs first, in routes.py), NOT the primary authorization
    # boundary. A card is authored by handler code (server-side, already
    # trusted); a grant's allowed_handlers is authored by the parent issuer.
    # So a handler self-declaring required_scope=None only drops the scope
    # refinement — it can still only be called if the operator granted it.
    required_scope: str | None = None


class CardValidationError(ValueError):
    """Raised when a capability card is structurally invalid."""


def validate_card(raw: dict[str, Any]) -> CapabilityCard:
    """Parse a capability-card dict. Raises CardValidationError on bad input."""
    try:
        return CapabilityCard.model_validate(raw)
    except ValidationError as exc:
        raise CardValidationError(str(exc)) from exc
