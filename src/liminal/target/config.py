"""Typed target configuration — the ``TargetSpec`` union.

Shaped like agentgateway's ``McpTargetSpec`` so liminal can optionally compose
behind agentgateway later without a config rewrite (the #5 swappability
insurance). #12 ships this minimal loader; #15 adds the versioned/validated
declarative schema.

One ``TargetSpec`` describes one federated target:

    [[target]]
    name = "jira"
    transport = "http"          # http | stdio
    address = "https://jira-mcp.internal/mcp"
    trust = "untrusted"         # trusted | untrusted (default untrusted for http/stdio)
    on_untrusted = "flag"       # flag | strip | block
    identity = "forward"        # forward | none  (http only)
    required_scope = "jira:use"  # scope a grant must hold for ANY tool here

    [target.tool_scopes]         # per-tool refinement (liminal#78)
    "create_issue" = "jira:write"
    "search" = "jira:read"

Validation is loud (``TargetConfigError``, a ``ValueError``) — No Silent
Failures. In particular a ``stdio`` target that asks for per-request identity
(``identity="forward"`` or ``auth_method="service-token"``) is rejected: stdio
children discard per-request headers, so they are identity-agnostic only (the
hard constraint from the agentgateway eval / fold-in #13).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, get_args

Transport = Literal["http", "stdio"]
Trust = Literal["trusted", "untrusted"]
OnUntrusted = Literal["flag", "strip", "block"]
Identity = Literal["forward", "none"]
AuthMethod = Literal["bearer", "service-token", "none"]

_TRANSPORTS = frozenset(get_args(Transport))
_TRUSTS = frozenset(get_args(Trust))
_ON_UNTRUSTED = frozenset(get_args(OnUntrusted))
_IDENTITIES = frozenset(get_args(Identity))
_AUTH_METHODS = frozenset(get_args(AuthMethod))


class TargetConfigError(ValueError):
    """Raised for an invalid or conflicting target configuration."""


@dataclass(slots=True)
class TargetSpec:
    """One federated target's configuration.

    Attributes:
        name: The namespace / authz key. Becomes the tool prefix
            (``"{name}.{tool}"``). Must be non-empty and contain no ``.``.
        transport: ``"http"`` (Streamable-HTTP MCP upstream) or ``"stdio"``
            (spawned MCP child — Stage B; config is validated here now).
        address: The upstream endpoint URL (required for ``http``).
        command: The child process argv (required for ``stdio``).
        trust: ``"trusted"`` | ``"untrusted"``. ``http``/``stdio`` default to
            ``"untrusted"`` so their catalogs are inspected at ingest.
        on_untrusted: Policy applied to flagged tools of an untrusted target
            — ``"flag"`` (annotate), ``"strip"`` (neutral stub), ``"block"``
            (drop).
        identity: ``"forward"`` forwards the caller's persona/issuer as
            per-call headers (``http`` only); ``"none"`` sends no identity.
        auth_method: Upstream auth — ``"bearer"`` (static token),
            ``"service-token"`` (per-call ``ctx.credentials[credential_key]``),
            or ``"none"``.
        bearer_token: Required when ``auth_method == "bearer"``.
        credential_key: Required when ``auth_method == "service-token"``.
        timeout_seconds: Per-call timeout for forwarded requests.
        refresh_tools_interval_seconds: Background catalog re-fetch cadence.
            ``0`` disables periodic refresh (still fetched once at startup).
        relevance_signals: Free-form routing hints for the capability surface.
        client_name: Advertised in the upstream ``initialize`` handshake.
        required_scope: The sovereign scope a grant must hold to invoke ANY
            tool on this target. ``None`` = no target-level gate. This is the
            federated analogue of ``CapabilityCard.required_scope``, but it is
            OPERATOR-authored rather than derived from the upstream catalog —
            see ``tool_scopes`` for why.
        tool_scopes: Per-tool scope refinement, keyed by the UNprefixed
            upstream tool name (``"create_issue"``, not ``"jira.create_issue"``).
            Overrides ``required_scope`` for that tool.

            **Declaring this turns the target deny-by-default** (liminal#78): a
            tool on this target that appears in neither ``tool_scopes`` nor
            ``required_scope`` resolves to an unsatisfiable scope, so a new tool
            appearing in a refreshed upstream catalog is denied until an
            operator names it. Leave empty to keep the target open (subject to
            ``required_scope`` and the operator's ``allowed_handlers`` grant).

            These live in operator config and NOT in the fetched catalog on
            purpose. An ``untrusted`` upstream authors its own catalog, so a
            catalog-derived scope map would let the upstream declare that its
            most dangerous tool needs no scope. ``CapabilityCard`` can be
            trusted for this because handler code is server-side; a federated
            catalog cannot.
    """

    name: str
    transport: Transport = "http"
    address: str = ""
    command: tuple[str, ...] = ()
    trust: Trust = "untrusted"
    on_untrusted: OnUntrusted = "flag"
    identity: Identity = "none"
    auth_method: AuthMethod = "none"
    bearer_token: str | None = None
    credential_key: str | None = None
    timeout_seconds: float = 30.0
    refresh_tools_interval_seconds: int = 300
    relevance_signals: tuple[str, ...] = ()
    client_name: str = "liminal-target"
    required_scope: str | None = None
    tool_scopes: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        """Raise ``TargetConfigError`` on any invalid combination."""
        if not self.name or "." in self.name:
            raise TargetConfigError(
                f"target name {self.name!r} must be non-empty and contain no "
                "'.' (it becomes the tool-name prefix / authz key)"
            )
        if self.transport not in _TRANSPORTS:
            raise TargetConfigError(
                f"target {self.name!r}: transport {self.transport!r} must be "
                f"one of {sorted(_TRANSPORTS)}"
            )
        if self.trust not in _TRUSTS:
            raise TargetConfigError(
                f"target {self.name!r}: trust {self.trust!r} must be one of "
                f"{sorted(_TRUSTS)}"
            )
        if self.on_untrusted not in _ON_UNTRUSTED:
            raise TargetConfigError(
                f"target {self.name!r}: on_untrusted {self.on_untrusted!r} must "
                f"be one of {sorted(_ON_UNTRUSTED)}"
            )
        if self.identity not in _IDENTITIES:
            raise TargetConfigError(
                f"target {self.name!r}: identity {self.identity!r} must be one "
                f"of {sorted(_IDENTITIES)}"
            )
        if self.auth_method not in _AUTH_METHODS:
            raise TargetConfigError(
                f"target {self.name!r}: auth_method {self.auth_method!r} must be "
                f"one of {sorted(_AUTH_METHODS)}"
            )
        if self.auth_method == "bearer" and not self.bearer_token:
            raise TargetConfigError(
                f"target {self.name!r}: auth_method='bearer' requires bearer_token"
            )
        if self.auth_method == "service-token" and not self.credential_key:
            raise TargetConfigError(
                f"target {self.name!r}: auth_method='service-token' requires "
                "credential_key"
            )

        if self.required_scope is not None and not str(self.required_scope).strip():
            raise TargetConfigError(
                f"target {self.name!r}: required_scope must be a non-empty "
                "string or omitted"
            )
        if not isinstance(self.tool_scopes, dict):
            raise TargetConfigError(
                f"target {self.name!r}: tool_scopes must be a table mapping "
                f"tool name -> scope, got {type(self.tool_scopes).__name__!r}"
            )
        for tool, scope in self.tool_scopes.items():
            if not isinstance(tool, str) or not tool.strip():
                raise TargetConfigError(
                    f"target {self.name!r}: tool_scopes has an empty/non-string "
                    f"tool name ({tool!r})"
                )
            if not isinstance(scope, str) or not scope.strip():
                raise TargetConfigError(
                    f"target {self.name!r}: tool_scopes[{tool!r}] must be a "
                    f"non-empty scope string, got {scope!r}"
                )

        if self.transport == "http":
            if not self.address:
                raise TargetConfigError(
                    f"target {self.name!r}: http transport requires an address"
                )
        elif self.transport == "stdio":
            if not self.command:
                raise TargetConfigError(
                    f"target {self.name!r}: stdio transport requires a command"
                )
            # Hard constraint (#13): stdio children discard per-request headers,
            # so they cannot carry per-request identity. Reject loudly rather
            # than silently drop the caller's identity.
            if self.identity == "forward":
                raise TargetConfigError(
                    f"target {self.name!r}: stdio targets cannot forward "
                    "per-request identity (identity='forward') — stdio children "
                    "discard per-request headers. Use transport='http' for "
                    "identity-forwarding, or set identity='none'."
                )
            if self.auth_method == "service-token":
                raise TargetConfigError(
                    f"target {self.name!r}: stdio targets cannot use "
                    "auth_method='service-token' — per-call credential headers "
                    "do not reach a stdio child. stdio targets are "
                    "identity-agnostic only."
                )


def load_target_specs(raw_targets: list[dict[str, Any]]) -> list[TargetSpec]:
    """Build + validate ``TargetSpec`` s from a list of ``[[target]]`` tables.

    Minimal loader for the #12 config path. Each dict is a decoded TOML table.
    Unknown keys are rejected loudly so a typo can't silently no-op.
    """
    known = {f for f in TargetSpec.__dataclass_fields__}
    specs: list[TargetSpec] = []
    for i, raw in enumerate(raw_targets):
        if not isinstance(raw, dict):
            raise TargetConfigError(
                f"[[target]] #{i} must be a table, got {type(raw).__name__!r}"
            )
        unknown = set(raw) - known
        if unknown:
            raise TargetConfigError(
                f"[[target]] #{i} ({raw.get('name')!r}) has unknown key(s): "
                f"{sorted(unknown)}. Known keys: {sorted(known)}"
            )
        data = dict(raw)
        # Normalize list-valued TOML fields to the tuples the dataclass expects.
        if "command" in data and isinstance(data["command"], list):
            data["command"] = tuple(data["command"])
        if "relevance_signals" in data and isinstance(data["relevance_signals"], list):
            data["relevance_signals"] = tuple(data["relevance_signals"])
        try:
            spec = TargetSpec(**data)
        except TypeError as exc:
            raise TargetConfigError(
                f"[[target]] #{i} ({raw.get('name')!r}): {exc}"
            ) from exc
        spec.validate()
        specs.append(spec)
    return specs
