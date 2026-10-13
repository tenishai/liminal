"""Typed target configuration — the ``TargetSpec`` union.

Shaped like agentgateway's ``McpTargetSpec`` so liminal can optionally compose
behind agentgateway later without a config rewrite (the #5 swappability
insurance). #12 ships this minimal loader; #15 adds the versioned/validated
declarative schema.

One ``TargetSpec`` describes one federated target:

    [[target]]
    name = "jira"
    transport = "http"          # http | stdio
    address = "https://jira-mcp.internal"   # base URL; the client appends /mcp
    trust = "untrusted"         # trusted | untrusted (default untrusted for http/stdio)
    on_untrusted = "flag"       # flag | strip | block
    identity = "forward"        # forward | none  (http only)
    required_scope = "jira:use"  # scope a grant must hold for ANY tool here
    session = "none"            # none | per-persona (stateful upstreams, liminal#172)

    [target.tool_scopes]         # per-tool refinement (liminal#78)
    "create_issue" = "jira:write"
    "search" = "jira:read"

    [target.headers]             # static request headers (http only, liminal#130)
    X-MCP-Readonly = "true"

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
AuthScheme = Literal["bearer", "basic"]
Session = Literal["none", "per-persona"]

_TRANSPORTS = frozenset(get_args(Transport))
_TRUSTS = frozenset(get_args(Trust))
_ON_UNTRUSTED = frozenset(get_args(OnUntrusted))
_IDENTITIES = frozenset(get_args(Identity))
_AUTH_METHODS = frozenset(get_args(AuthMethod))
_AUTH_SCHEMES = frozenset(get_args(AuthScheme))
_SESSIONS = frozenset(get_args(Session))

# RFC 9110 field-name: a token. Anything else (spaces, colons, controls) is
# refused by the HTTP library on the first request, so it is refused here, at
# load (liminal#141).
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

# Header names liminal sets itself (lowercase; names are case-insensitive).
# Per-call identity headers (HttpTarget) -- defined here, not in http.py, so
# validation can see them without a circular import.
HEADER_PERSONA = "x-liminal-persona"
HEADER_ISSUER = "x-liminal-issuer"
HEADER_CORRELATION_ID = "x-correlation-id"

# A static `headers` table may not set any of these (liminal#130): credentials,
# forwarded identity, the session id, and the content negotiation the MCP client
# owns. Mirrors liminal.client.mcp (_base_headers, SESSION_HEADER, Authorization).
RESERVED_HEADERS = frozenset({
    "authorization",
    HEADER_PERSONA,
    HEADER_ISSUER,
    HEADER_CORRELATION_ID,
    "mcp-session-id",
    "accept",
    "content-type",
})


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
        address: The upstream's base URL (required for ``http``), without
            the ``/mcp`` path: the MCP client appends it, so an address that
            already ends in ``/mcp`` posts to ``/mcp/mcp`` (#69).
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
        bearer_token: The static credential, inline. When
            ``auth_method == "bearer"`` exactly one of ``bearer_token`` and
            ``bearer_token_env`` is required.
        bearer_token_env: Name of an env var holding the static credential,
            read when the target starts. Config files are reviewed and often
            baked into images, so a literal secret in ``bearer_token`` is a
            leak with a commit hash. An unset or empty variable fails the
            target's startup with an error naming the variable.
        auth_scheme: How the credential rides the ``Authorization`` header,
            for the static credential and for ``service-token`` alike.
            ``"bearer"`` (default) sends it verbatim as ``Bearer <value>``.
            ``"basic"`` treats the value as ``user:secret`` and base64-encodes
            it at the wire (``Basic base64(user:secret)``, as Atlassian's
            hosted MCP expects for service accounts), so the credential store
            holds the readable form, never a pre-encoded blob. ``"basic"``
            needs a credential (``auth_method`` ``"bearer"`` or
            ``"service-token"``).
        credential_key: Required when ``auth_method == "service-token"``.
        timeout_seconds: Per-call timeout for forwarded requests.
        refresh_tools_interval_seconds: Background catalog re-fetch cadence.
            ``0`` disables periodic refresh (still fetched once at startup).
        headers: Static request headers sent on every call to this target
            (``http`` only), e.g. ``{"X-MCP-Readonly": "true"}``. Names are
            case-insensitive; ``Authorization`` and every header liminal sets
            itself (``RESERVED_HEADERS``) are refused so a config can't
            override per-call credentials or forwarded identity.
        client_name: Advertised in the upstream ``initialize`` handshake.
        session: ``"none"`` (default) or ``"per-persona"`` (``http`` only).
            For a stateful upstream: one that returns an ``Mcp-Session-Id`` on
            ``initialize`` and refuses later requests without it. With
            ``"per-persona"`` each calling persona (issuer + identity) gets its
            own upstream session, opened with that persona's credential on its
            first call, and the catalog fetch gets a separate one that no
            persona call uses, so a session never rides another persona's call
            (liminal#76, liminal#172). An expired session (404) is reopened
            once. ``"none"`` keeps the gateway stateless: no session id is
            ever kept or sent.
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
    bearer_token_env: str | None = None
    credential_key: str | None = None
    auth_scheme: AuthScheme = "bearer"
    timeout_seconds: float = 30.0
    refresh_tools_interval_seconds: int = 300
    client_name: str = "liminal-target"
    required_scope: str | None = None
    tool_scopes: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    session: Session = "none"

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
        if self.auth_scheme not in _AUTH_SCHEMES:
            raise TargetConfigError(
                f"target {self.name!r}: auth_scheme {self.auth_scheme!r} must "
                f"be one of {sorted(_AUTH_SCHEMES)}"
            )
        if self.session not in _SESSIONS:
            raise TargetConfigError(
                f"target {self.name!r}: session {self.session!r} must be one of "
                f"{sorted(_SESSIONS)}"
            )
        if self.auth_scheme == "basic" and self.auth_method == "none":
            raise TargetConfigError(
                f"target {self.name!r}: auth_scheme='basic' needs a credential "
                "(auth_method 'bearer' or 'service-token')"
            )
        if self.bearer_token_env is not None and (
            not isinstance(self.bearer_token_env, str) or not self.bearer_token_env.strip()
        ):
            raise TargetConfigError(
                f"target {self.name!r}: bearer_token_env must name an "
                f"environment variable, got {self.bearer_token_env!r}"
            )
        if self.bearer_token_env is not None and self.auth_method != "bearer":
            # The key exists to move a secret out of the file; set without
            # auth_method="bearer" it was read by nothing, and the target
            # called its upstream anonymously.
            raise TargetConfigError(
                f"target {self.name!r}: bearer_token_env is set but auth_method "
                f"is {self.auth_method!r}; it is read only for auth_method='bearer'"
            )
        if self.auth_method == "bearer" and self.bearer_token and self.bearer_token_env:
            raise TargetConfigError(
                f"target {self.name!r}: bearer_token and bearer_token_env are "
                "mutually exclusive -- pick where the credential lives"
            )
        if self.auth_method == "bearer" and not (self.bearer_token or self.bearer_token_env):
            raise TargetConfigError(
                f"target {self.name!r}: auth_method='bearer' requires "
                "bearer_token or bearer_token_env"
            )
        if self.auth_method == "service-token" and not self.credential_key:
            raise TargetConfigError(
                f"target {self.name!r}: auth_method='service-token' requires "
                "credential_key"
            )

        # `str(...)` COERCION WAS A FAIL-OPEN. It let every non-string through,
        # and the falsy ones -- 0, False, [], {} -- are all valid TOML. app.py
        # then gates on `if spec.required_scope:`, so a falsy value is silently
        # DROPPED from the scope map, leaving a target with no tool_scopes
        # WHOLLY OPEN. Deny-by-default catches it only when tool_scopes is
        # present. (Prudence, liminal#81 round 2 — she under-tiered this as a
        # symmetry nit in round 1 and re-graded it after tracing the drop.)
        if self.required_scope is not None and not isinstance(self.required_scope, str):
            raise TargetConfigError(
                f"target {self.name!r}: required_scope must be a string or "
                f"omitted, got {type(self.required_scope).__name__!r}"
            )
        if self.required_scope is not None and not self.required_scope.strip():
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

        if not isinstance(self.headers, dict):
            raise TargetConfigError(
                f"target {self.name!r}: headers must be a table mapping header "
                f"name -> value, got {type(self.headers).__name__!r}"
            )
        seen_headers: dict[str, str] = {}
        for hname, hvalue in self.headers.items():
            if not isinstance(hname, str) or not hname.strip():
                raise TargetConfigError(
                    f"target {self.name!r}: headers has an empty/non-string "
                    f"header name ({hname!r})"
                )
            if not isinstance(hvalue, str):
                raise TargetConfigError(
                    f"target {self.name!r}: headers[{hname!r}] must be a string, "
                    f"got {type(hvalue).__name__!r}"
                )
            # The name is sent exactly as written, so it is checked exactly as
            # written: no strip, which used to let " X-Foo " load and then
            # fail inside the HTTP library (liminal#141).
            if not set(hname) <= _TOKEN_CHARS:
                raise TargetConfigError(
                    f"target {self.name!r}: header name {hname!r} is not a valid "
                    "HTTP field name (letters, digits and !#$%&'*+-.^_`|~ only, "
                    "no spaces)"
                )
            if any(c in hvalue for c in "\r\n\0"):
                raise TargetConfigError(
                    f"target {self.name!r}: headers[{hname!r}] contains a CR, LF "
                    "or NUL character"
                )
            folded = hname.lower()
            if folded in seen_headers:
                raise TargetConfigError(
                    f"target {self.name!r}: headers names {seen_headers[folded]!r} "
                    f"and {hname!r} are the same header (names are "
                    "case-insensitive); declare it once"
                )
            seen_headers[folded] = hname
            if folded in RESERVED_HEADERS:
                raise TargetConfigError(
                    f"target {self.name!r}: headers may not set {hname!r} — "
                    "liminal owns credentials, forwarded identity, the session "
                    f"id and content negotiation (reserved: "
                    f"{sorted(RESERVED_HEADERS)})"
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
            if self.session != "none":
                raise TargetConfigError(
                    f"target {self.name!r}: session applies to http targets "
                    "only; a stdio child is one process with one session"
                )
            if self.headers:
                raise TargetConfigError(
                    f"target {self.name!r}: stdio targets cannot set headers — "
                    "there is no HTTP request to carry them. Use "
                    "transport='http'."
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
        try:
            spec = TargetSpec(**data)
        except TypeError as exc:
            raise TargetConfigError(
                f"[[target]] #{i} ({raw.get('name')!r}): {exc}"
            ) from exc
        spec.validate()
        specs.append(spec)
    return specs
