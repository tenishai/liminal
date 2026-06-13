"""Register MCP proxy handlers into limenal's runtime registry.

Operators (or the app factory) pass a list of ProxyConfig at startup;
this module materializes one MCPProxyHandler per config and adds them
to the registry under their configured prefix names.

Why not entry-points: each upstream is operator-config, not a Python
package. Forcing operators to declare entry-points for Jira / Slack /
their own personas would be heavy. Runtime registration via
register_explicit() is exactly the escape hatch limenal already
provides for embedded-use cases.
"""

from __future__ import annotations

from limenal.handlers.mcp_proxy.config import ProxyConfig
from limenal.handlers.mcp_proxy.handler import MCPProxyHandler
from limenal.protocol.card import validate_card
from limenal.registry import HandlerRecord, Registry


class ProxyRegistrationError(ValueError):
    """Raised at registration time for invalid or conflicting config."""


def register_proxies(
    registry: Registry,
    configs: list[ProxyConfig],
) -> list[MCPProxyHandler]:
    """Materialize handlers from configs and add them to ``registry``.

    Returns the list of handler instances in the same order as configs
    so the caller (typically ``create_app``'s lifespan) can call
    ``await handler.startup()`` on each.

    Raises:
        ProxyRegistrationError: on validation errors, prefix collisions
            with already-registered handlers, or duplicate prefixes
            within ``configs``.
    """
    seen_prefixes: set[str] = set()
    handlers: list[MCPProxyHandler] = []

    for config in configs:
        try:
            config.validate()
        except ValueError as exc:
            raise ProxyRegistrationError(
                f"invalid proxy config (prefix={config.prefix!r}): {exc}"
            ) from exc

        if config.prefix in seen_prefixes:
            raise ProxyRegistrationError(
                f"duplicate proxy prefix {config.prefix!r} in proxy configs"
            )

        if registry.get(config.prefix) is not None:
            raise ProxyRegistrationError(
                f"proxy prefix {config.prefix!r} collides with an "
                "already-registered handler"
            )

        handler = MCPProxyHandler(config=config)
        # Card validation runs against the upstream's eventual catalog —
        # at register time it's empty. Pass a minimal placeholder card so
        # the Registry's invariants stay satisfied; startup() refreshes it.
        placeholder_card = {
            "handler": config.prefix,
            "description": (
                f"MCP proxy → {config.upstream_url} (tools refresh at startup)."
            ),
            "tools": [],
            "activation": "always",
            "relevance_signals": list(config.relevance_signals),
            "credential_keys": [],
        }
        card = validate_card(placeholder_card)
        record = HandlerRecord(
            name=config.prefix,
            handler=handler,
            card=card,
            source=f"mcp_proxy({config.upstream_url})",
        )
        registry.register(record)
        seen_prefixes.add(config.prefix)
        handlers.append(handler)

    return handlers
