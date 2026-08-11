"""Discover and register Handlers from the `liminal.handlers` entry-point group.

Discovery is fail-open per design.md §"Failure posture":
  - A handler whose import raises is logged and skipped — other handlers
    still register.
  - A handler whose capability card is malformed is logged and skipped.
  - The list_tools surface is built only from the handlers that survived
    discovery; a broken handler doesn't black-hole the agent's tool surface.

Security-critical operations (credential resolution, future handler
registration RPCs) fail closed and live elsewhere — registry discovery is
strictly the visibility surface.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from importlib.metadata import entry_points

import structlog

from liminal.protocol import (
    CapabilityCard,
    CardValidationError,
    Handler,
    validate_card,
)

log = structlog.get_logger(__name__)

ENTRY_POINT_GROUP = "liminal.handlers"


class DiscoveryError(RuntimeError):
    """Raised when registry build cannot proceed at all (e.g., the entry-
    point group itself is unreadable). Per-handler failures are caught
    and logged, not raised."""


@dataclass(slots=True)
class HandlerRecord:
    """A registered handler with its validated card."""

    name: str
    handler: Handler
    card: CapabilityCard
    source: str  # entry-point distribution + module path, for diagnostics


class Registry:
    """Name-keyed handler store. Read-mostly after registration."""

    def __init__(self) -> None:
        self._records: dict[str, HandlerRecord] = {}

    def register(self, record: HandlerRecord) -> None:
        if record.name in self._records:
            log.warning(
                "registry.duplicate_handler",
                name=record.name,
                existing=self._records[record.name].source,
                new=record.source,
                msg="last one wins",
            )
        self._records[record.name] = record

    def get(self, name: str) -> HandlerRecord | None:
        return self._records.get(name)

    def names(self) -> list[str]:
        return sorted(self._records.keys())

    def __iter__(self) -> Iterator[HandlerRecord]:
        return iter(self._records.values())

    def __len__(self) -> int:
        return len(self._records)


def discover_handlers(
    *,
    group: str = ENTRY_POINT_GROUP,
    only: list[str] | None = None,
) -> Registry:
    """Scan the entry-point group; instantiate handlers + validate cards.

    `only` filters discovery to a specific set of entry-point names. Useful
    for tests and for the operator's `toolset.yaml` flow which can disable
    specific handlers per persona.
    """
    registry = Registry()
    try:
        eps = entry_points(group=group)
    except Exception as exc:  # noqa: BLE001
        raise DiscoveryError(f"entry-point group {group!r} unreadable: {exc}") from exc

    for ep in eps:
        if only is not None and ep.name not in only:
            continue
        try:
            factory = ep.load()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "registry.import_failed", entry=ep.name, error=str(exc)
            )
            continue
        try:
            handler = factory()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "registry.factory_failed", entry=ep.name, error=str(exc)
            )
            continue
        if not isinstance(handler, Handler):
            log.warning(
                "registry.handler_protocol_mismatch",
                entry=ep.name,
                type=type(handler).__name__,
            )
            continue
        try:
            card_raw = handler.capability_card()
            card = validate_card(card_raw)
        except CardValidationError as exc:
            log.warning(
                "registry.card_invalid", entry=ep.name, error=str(exc)
            )
            continue
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "registry.card_unreadable", entry=ep.name, error=str(exc)
            )
            continue
        source = f"{ep.value} (dist={(ep.dist.name + '@' + (ep.dist.version or '?')) if ep.dist else 'unknown'})"
        registry.register(
            HandlerRecord(name=ep.name, handler=handler, card=card, source=source)
        )
        log.info("registry.registered", handler=ep.name, source=source)

    return registry


def register_explicit(registry: Registry, name: str, handler: Handler, *, source: str = "explicit") -> None:
    """For tests and embedding scenarios where the consumer wires handlers
    in code rather than going through entry-points."""
    try:
        card = validate_card(handler.capability_card())
    except CardValidationError as exc:
        raise DiscoveryError(f"handler {name!r} card invalid: {exc}") from exc
    registry.register(HandlerRecord(name=name, handler=handler, card=card, source=source))
