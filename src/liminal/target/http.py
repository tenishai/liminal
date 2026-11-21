"""``HttpTarget`` — a Streamable-HTTP MCP upstream as a Target.

Generalizes the retired ``MCPProxyHandler``: it fetches + inspects the
upstream's tool catalog at ingest, and forwards calls with **per-call**
identity. It folds in three things the old proxy lacked or did unsafely:

  - **#79 result framing** — an ``UNTRUSTED`` target's tool RESULTS are
    wrapped in a nonce-tagged envelope at dispatch and flagged in the response
    ``_meta``, so instruction-shaped text an upstream returns is marked as
    data rather than flowing to the agent verbatim.
  - **#16 catalog inspection** — an ``UNTRUSTED`` target's catalog is passed
    through ``inspect_catalog`` at ingest (the single chokepoint) before the
    tools ever reach a persona's context.
  - **#13 per-call identity (no shared mutable token)** — the old proxy
    mutated a *shared* client's token in place per call, a cross-persona
    credential-leak footgun. Here every dispatch builds fresh per-call headers
    (persona / issuer / correlation-id, and a per-call ``Authorization`` for
    service-token auth) and passes them as a local argument. Nothing
    persona-specific is ever stored on the client, so concurrent dispatches
    can't leak each other's tokens.
  - **#27 correlation-id** — carried on ``ctx.extra["correlation_id"]``
    (generated if absent) and forwarded as ``x-correlation-id`` on every call.

Failure modes stay explicit (No Silent Failures): ANY failed catalog fetch
— startup or periodic refresh — sets a ``catalog_status`` the health surface
reports as degraded until a fetch succeeds again, never a silently-empty or
silently-stale tool list (liminal#75); only the log severity differs
(error at startup, warning on a refresh, where the last good catalog keeps
serving); a service-token call whose credential did not resolve is REFUSED
with a failure naming the missing key, never sent upstream unauthenticated
(liminal#80); upstream 4xx/5xx or transport error mid-call →
``ToolResult.failure`` with the cause.

Two deployment notes. The owned HTTP client rejects every cookie (a blocking
cookie policy): upstream ``Set-Cookie`` never persists, so one persona's
upstream session can never ride another persona's call (liminal#76) — an
injected ``http_client`` is the injector's responsibility. A stateful
upstream (``session = "per-persona"``, liminal#172) gets the same guarantee
for ``Mcp-Session-Id`` by structure: each persona has its own client object
holding its own session id, and the catalog fetch has another. And because this
gateway holds credentials for its targets, its pod's egress should be
allowlisted to exactly the declared target addresses (liminal#80).
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import os
import uuid
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

import httpx
import structlog

from liminal.client.mcp import (
    AsyncMCPClient,
    MCPError,
    MCPRemoteError,
    MCPSessionExpired,
    ToolCallOutcome,
    authorization_value,
)
from liminal.protocol import Context, ToolResult, ToolSpec
from liminal.target.base import Target, TrustTier
from liminal.target.catalog_tokens import CatalogTokenProvider, load_catalog_token_provider
from liminal.target.config import (
    HEADER_CORRELATION_ID,
    HEADER_ISSUER,
    HEADER_PERSONA,
    TargetConfigError,
    TargetSpec,
)
from liminal.target.inspect import (
    UnsanitizableResult,
    frame_untrusted_result,
    inspect_catalog,
    is_empty_result,
    new_envelope_nonce,
)

log = structlog.get_logger(__name__)

# Per-call header names live in target.config (imported above) so config
# validation can reserve them.
CORRELATION_ID_KEY = "correlation_id"


# How many per-persona upstream sessions one target keeps (liminal#172). The
# least recently used is dropped past this, and that persona opens a new one
# on its next call. Personas are operator-granted, so this is a backstop.
MAX_PERSONA_SESSIONS = 256

# The per-call Authorization value. The same function the client uses for its
# base header, so bearer vs basic has one encoding rule.
_authorization = authorization_value


_SESSION_LOST_WORDS = ("missing session", "no session", "unknown session", "session not found",
                       "session expired", "invalid session")


def _session_lost(exc: MCPRemoteError) -> bool:
    """Whether an upstream's JSON-RPC error says the session is gone (a server
    that does not use the spec's 404 for it)."""
    message = (exc.message or "").lower()
    return any(words in message for words in _SESSION_LOST_WORDS)


class _MissingCredential(Exception):
    """A service-token dispatch whose credential did not resolve; str() is
    the credential key. Rendered by dispatch() as a refusal (liminal#80)."""


class HttpTarget(Target):
    """One HTTP MCP upstream, namespaced under ``spec.name``."""

    def __init__(
        self,
        spec: TargetSpec,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if spec.transport != "http":
            raise TargetConfigError(
                f"HttpTarget requires transport='http', got {spec.transport!r} "
                f"for target {spec.name!r}"
            )
        spec.validate()
        self.spec = spec
        self.name = spec.name
        self.trust = TrustTier(spec.trust)

        self._http_client = http_client
        self._owned_http = False
        self._client: AsyncMCPClient | None = None
        self._tools: list[ToolSpec] = []
        self._refresh_task: asyncio.Task[None] | None = None
        self._protocol_version: str | None = None
        # session="per-persona" only: (issuer, identity) -> that persona's own
        # client, holding that persona's Mcp-Session-Id and nothing else
        # (liminal#172). The lock serialises opening a session, not calls.
        self._sessions: OrderedDict[tuple[str, str], AsyncMCPClient] = OrderedDict()
        self._session_locks: dict[tuple[str, str], asyncio.Lock] = {}
        # Surfaced by /healthz (liminal#75): "not started" -> "ready" on a
        # successful catalog fetch, or "catalog fetch failed: ..." -- a failed
        # target is visible, never a silently-empty tool list.
        self.catalog_status: str = "not started"
        # catalog_token_provider only: the provider, loaded at startup, and the
        # token it minted last, which the CATALOG client's token_provider
        # returns. Persona clients never read it (their token provider is the
        # base one, empty for service-token / service-headers).
        self._catalog_token_provider: CatalogTokenProvider | None = None
        self._catalog_token: str = ""

    # ---- Target protocol --------------------------------------------------

    async def list_tools(self) -> list[ToolSpec]:
        # Returns the cached, already-inspected catalog. Empty until startup
        # (or if the upstream was unreachable) — same posture as the old proxy.
        return list(self._tools)

    async def dispatch(
        self, tool: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        if self._client is None:
            return ToolResult.failure(
                f"target {self.name!r} not started (call startup() first)"
            )

        try:
            headers = self._build_call_headers(ctx)
        except _MissingCredential as exc:
            log.warning(
                "http_target.credential_missing",
                target=self.name,
                persona=ctx.identity,
                credential_key=str(exc),
            )
            return ToolResult.failure(
                f"credential {exc} for persona {ctx.identity!r} did not "
                f"resolve; refusing to call {self.name!r} unauthenticated"
            )
        log.debug(
            "http_target.dispatch",
            target=self.name,
            tool=tool,
            persona=ctx.identity,
            correlation_id=headers.get(HEADER_CORRELATION_ID),
        )
        try:
            if self.spec.session == "per-persona":
                outcome: ToolCallOutcome = await self._call_in_session(
                    ctx, tool, payload, headers
                )
            else:
                outcome = await self._client.call_tool(
                    tool, payload, extra_headers=headers
                )
        except MCPRemoteError as exc:
            return self._error_result(
                reason=f"upstream {self.name!r} returned error [{exc.code}]",
                upstream_text=exc.message,
            )
        except MCPError as exc:
            # An MCPTransportError message can embed the upstream's response
            # body (`server {status}: {resp.text[:200]}`), so this is not
            # unconditionally our own prose either.
            return self._error_result(
                reason=f"upstream {self.name!r} transport error",
                upstream_text=str(exc),
            )

        content = list(outcome.content)
        if self.trust is TrustTier.UNTRUSTED:
            # #79 — the dispatch-time half of #16. Catalog inspection covers
            # what the upstream SAYS about its tools; this covers what it
            # RETURNS. The nonce goes out-of-band in the response `_meta` so a
            # runtime can verify the delimiters instead of trusting their shape.
            nonce = new_envelope_nonce()
            try:
                framed = frame_untrusted_result(content, self.name, nonce)
            except UnsanitizableResult as exc:
                # Fail closed, and fail as a ToolResult rather than letting the
                # exception propagate. NOT because it would reach Starlette —
                # Multiplexer.dispatch has a blanket `except Exception` and is
                # the only dispatcher wired, so it would not. The reason is that
                # a propagated exception yields "evil.search raised
                # UnsanitizableResult", while returning here yields a refusal
                # that names the target, the cause, and the disposition.
                # (Prudence, liminal#82 rounds 3 and 4 — one of five sites of
                # the retracted "unhandled 500" claim; the correction lives in
                # inspect.py beside MAX_CONTENT_DEPTH.)
                log.warning(
                    "http_target.result_unsanitizable",
                    target=self.name, tool=tool, error=str(exc),
                )
                return ToolResult.failure(
                    f"refused: {self.name!r} returned content that could not be "
                    f"sanitised ({exc}); it is not forwarded"
                )
            if is_empty_result(content):
                log.warning(
                    "http_target.result_empty",
                    target=self.name, tool=tool, is_error=outcome.is_error,
                )
            return ToolResult(
                content=framed,
                is_error=outcome.is_error,
                liminal_untrusted=True,
                liminal_untrusted_source=self.name,
                liminal_untrusted_nonce=nonce,
            )
        return ToolResult(content=content, is_error=outcome.is_error)

    def protocol_version(self) -> str | None:
        return self._protocol_version

    # ---- lifecycle --------------------------------------------------------

    async def _mint_catalog_token(self) -> None:
        """Ask the catalog token provider for the bearer the next catalog
        fetch carries. A provider that raises propagates; one that returns an
        empty or whitespace-only value is a wiring error named here, since an
        empty bearer would mean an unauthenticated fetch (the header is
        omitted for an empty token) against an upstream that refuses one."""
        assert self._catalog_token_provider is not None
        token = (await self._catalog_token_provider() or "").strip()
        if not token:
            raise RuntimeError(
                f"target {self.spec.name!r}: catalog_token_provider "
                f"{self.spec.catalog_token_provider!r} returned an empty token"
            )
        self._catalog_token = token

    def _catalog_headers(self) -> dict[str, str]:
        """``catalog_headers_env`` resolved, at startup, for the catalog client
        alone. A named variable that is unset, empty or whitespace-only is a
        wiring error like ``bearer_token_env``'s: it raises, naming the
        variable, before anything is opened or sent."""
        resolved: dict[str, str] = {}
        for hname, env_name in self.spec.catalog_headers_env.items():
            value = (os.environ.get(env_name) or "").strip()
            if not value:
                raise RuntimeError(
                    f"target {self.spec.name!r}: catalog_headers_env[{hname!r}] "
                    f"${env_name} is unset or empty"
                )
            resolved[hname] = value
        return resolved

    def _static_token(self) -> str:
        """The static credential for ``auth_method="bearer"``, else ``""``.

        ``bearer_token_env`` is read here, at startup. A named variable that
        is unset or empty is a wiring error, not a no-auth deployment: it
        raises, naming the variable, before anything is opened or sent."""
        if self.spec.auth_method != "bearer":
            return ""
        env_name = self.spec.bearer_token_env
        if env_name:
            token = (os.environ.get(env_name) or "").strip()
            if not token:
                raise RuntimeError(
                    f"target {self.spec.name!r}: bearer_token_env "
                    f"${env_name} is unset or empty"
                )
            return token
        return self.spec.bearer_token or ""

    async def startup(self) -> None:
        """Connect, initialize, fetch + inspect the catalog, schedule refresh."""
        # Resolve the static credential first so an unset bearer_token_env
        # fails before a client is built or a request leaves.
        base_token = self._static_token()
        catalog_headers = self._catalog_headers()
        if self.spec.catalog_token_provider:
            # Unknown or broken provider: fail here, before a client is built,
            # the same posture as an unset bearer_token_env.
            self._catalog_token_provider = load_catalog_token_provider(
                self.spec.catalog_token_provider
            )
        if self._http_client is None:
            # The owned client REJECTS every cookie (liminal#76): dispatches
            # for different personas share this one client, and an upstream
            # session cookie set on persona A's authenticated call must never
            # replay on persona B's. Stateless bearer-per-call is the model;
            # a blocking cookie policy makes it structural.
            no_cookies = http.cookiejar.CookieJar(
                policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[])
            )
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.spec.timeout_seconds),
                cookies=no_cookies,
            )
            self._owned_http = True

        # The base client carries NO persona-specific secret. For bearer auth
        # the static target token rides every base call -- the handshake AND
        # the catalog fetch (initialize authenticates like everything else
        # since liminal#75); for service-token / none the base token stays
        # empty, those base calls go out unauthenticated by design, and the
        # per-call Authorization is built fresh in dispatch (#13). base_token
        # was resolved by _static_token() above; auth_scheme decides how the
        # client encodes it on every base call.

        def _base_token_provider() -> str:
            return base_token

        self._base_token_provider = _base_token_provider
        # With session="per-persona" this client's session is the catalog
        # fetch's alone: dispatches go through _call_in_session instead. The
        # catalog headers ride this client only; a persona's session client
        # (_call_in_session) never carries them.
        # A catalog token provider gives the catalog client a token provider
        # of its own, reading the token minted before each fetch; base_token
        # (empty for these auth methods) stays with the persona clients.
        self._client = self._new_client(
            static_headers={**self.spec.headers, **catalog_headers},
            token_provider=(lambda: self._catalog_token) if self._catalog_token_provider else None,
        )

        if self._catalog_token_provider is not None:
            # Minted BEFORE the first fetch and outside its try: a provider
            # that cannot mint at startup fails the target like an unset
            # bearer_token_env does, naming the provider, rather than leaving
            # a target up with "catalog fetch failed".
            await self._mint_catalog_token()
        await self._refresh_tools_once(initialize=True)

        if self.spec.refresh_tools_interval_seconds > 0:
            self._refresh_task = asyncio.create_task(self._refresh_loop())

    def _new_client(
        self,
        *,
        static_headers: dict[str, str] | None = None,
        token_provider: Callable[[], str] | None = None,
    ) -> AsyncMCPClient:
        return AsyncMCPClient(
            base_url=self.spec.address,
            token_provider=token_provider or self._base_token_provider,
            http_client=self._http_client,
            client_name=self.spec.client_name,
            static_headers=self.spec.headers if static_headers is None else static_headers,
            auth_scheme=self.spec.auth_scheme,
            use_session=self.spec.session == "per-persona",
        )

    async def shutdown(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._refresh_task = None
        # End the upstream sessions while the HTTP client is still open.
        for client in [*self._sessions.values(), self._client]:
            if client is not None and self.spec.session == "per-persona":
                await client.terminate_session()
        self._sessions.clear()
        self._session_locks.clear()
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._owned_http and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
            self._owned_http = False

    # ---- internals --------------------------------------------------------

    def _error_result(self, *, reason: str, upstream_text: str) -> ToolResult:
        """A failed dispatch whose message may carry upstream-authored bytes.

        Since liminal#66 a ToolResult's ``.error`` is appended to the content
        the agent sees, so an error string is now an injection surface exactly
        like a successful result is. Both upstream error paths can embed
        upstream output — ``MCPRemoteError.message`` is the upstream's own
        JSON-RPC error text, and ``MCPTransportError`` embeds ``resp.text`` for
        a 5xx — so on an UNTRUSTED target the upstream half goes inside the
        envelope and ``.error`` keeps only liminal's own description.

        The result stays legible per #66: the agent still gets a reason, and
        still gets the upstream's text — framed rather than dropped.
        """
        if self.trust is not TrustTier.UNTRUSTED:
            return ToolResult.failure(f"{reason}: {upstream_text}")
        nonce = new_envelope_nonce()
        # GUARDED LIKE THE SUCCESS PATH. This call was unguarded, so an upstream
        # error message — MCPRemoteError.message is unvalidated — bypassed the
        # depth bound the success path enforces. The Multiplexer's blanket
        # except contains it, so this was a message-parity gap rather than a
        # crash: the caller got "raised UnsanitizableResult" instead of the
        # refusal prose. (Prudence, liminal#82 round 3, nit 3.)
        try:
            framed = frame_untrusted_result(
                [{"type": "text", "text": upstream_text}], self.name, nonce
            )
        except UnsanitizableResult as exc:
            return ToolResult.failure(
                f"{reason}, and the upstream's error text could not be "
                f"sanitised ({exc}); it is not forwarded"
            )
        return ToolResult(
            content=framed,
            is_error=True,
            error=reason,
            liminal_untrusted=True,
            liminal_untrusted_source=self.name,
            liminal_untrusted_nonce=nonce,
        )

    def _build_call_headers(self, ctx: Context) -> dict[str, str]:
        """Build fresh per-call headers. NEVER stored on the client (#13)."""
        headers: dict[str, str] = {}

        # #13 identity forwarding — the caller's persona/issuer as headers so
        # the backend can self-resolve its own creds from that identity.
        if self.spec.identity == "forward":
            headers[HEADER_PERSONA] = ctx.identity
            headers[HEADER_ISSUER] = ctx.issuer

        # service-token auth — resolve the per-call credential into a per-call
        # Authorization header. Not present on the shared client, so persona
        # A's token can never ride persona B's concurrent request. A missing
        # or empty credential is a REFUSAL, raised for dispatch() to render
        # (liminal#80) -- never an unauthenticated upstream attempt.
        if self.spec.auth_method == "service-token":
            key = self.spec.credential_key or ""
            # STRIP BEFORE TESTING. `if not token` catches "" and None but
            # not "   " — and a trailing newline is the shape a secret read
            # from a file arrives in. Driven: dialed=1, is_error=False,
            # auth='Bearer    ' (Prudence, liminal#84 r1). A whitespace-only
            # credential is a missing credential, and #80's guarantee is that
            # a missing credential is a refusal rather than an anonymous call.
            token = (ctx.credentials.get(key) or "").strip() if key else ""
            if not token:
                raise _MissingCredential(key or "(no credential_key configured)")
            headers["Authorization"] = _authorization(self.spec.auth_scheme, token)

        # service-headers auth — the same rule, one header per credential key:
        # every named header is built fresh from this call's credentials, and
        # any one of them missing or blank refuses the call (liminal#80). The
        # catalog's shared headers are on the catalog client only, so a
        # persona's call never falls back to them.
        if self.spec.auth_method == "service-headers":
            for hname, key in self.spec.credential_headers.items():
                value = (ctx.credentials.get(key) or "").strip()
                if not value:
                    raise _MissingCredential(key)
                headers[hname] = value

        # #27 correlation-id — carry an inbound one or generate, persist on the
        # context, and forward on every call for end-to-end traceability.
        correlation_id = ctx.extra.get(CORRELATION_ID_KEY)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            ctx.extra[CORRELATION_ID_KEY] = correlation_id
        headers[HEADER_CORRELATION_ID] = str(correlation_id)

        return headers

    async def _call_in_session(
        self, ctx: Context, tool: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> ToolCallOutcome:
        """Call ``tool`` inside this persona's own upstream session.

        The session is opened with this call's headers, so it carries this
        persona's credential and identity. A 404 on a session (expired, or the
        upstream restarted) reopens it and retries once; a second 404 is an
        error like any other."""
        key = (ctx.issuer, ctx.identity)
        for attempt in (1, 2):
            client = self._sessions.get(key)
            if client is None:
                client = self._sessions[key] = self._new_client()
                self._session_locks[key] = asyncio.Lock()
                while len(self._sessions) > MAX_PERSONA_SESSIONS:
                    old, _ = self._sessions.popitem(last=False)
                    self._session_locks.pop(old, None)
            self._sessions.move_to_end(key)
            async with self._session_locks[key]:
                if not client.initialized or not client.has_session:
                    # A client that is initialized but holds no session id
                    # (seen live against Datadog's hosted server: the first
                    # call went through, the next went out bare and met
                    # "missing session ID") is reopened rather than trusted
                    # to call bare (liminal#224).
                    if client.initialized:
                        log.info(
                            "http_target.session_missing",
                            target=self.name, persona=ctx.identity,
                        )
                        client.forget_session()
                    await client.initialize(extra_headers=headers)
                    log.debug(
                        "http_target.session_opened",
                        target=self.name, persona=ctx.identity,
                    )
            try:
                return await client.call_tool(tool, payload, extra_headers=headers)
            except MCPSessionExpired:
                if attempt == 2:
                    raise
                log.info(
                    "http_target.session_expired",
                    target=self.name, persona=ctx.identity,
                )
            except MCPRemoteError as exc:
                # The spec says a gone session is a 404, and some servers say it
                # as a JSON-RPC error instead ("missing session ID", seen live
                # from Datadog's hosted server after one call). Same remedy:
                # forget it, reopen once, retry once (liminal#224).
                if attempt == 2 or not _session_lost(exc):
                    raise
                log.info(
                    "http_target.session_lost",
                    target=self.name, persona=ctx.identity, message=exc.message[:120],
                )
                client.forget_session()
        raise AssertionError("unreachable")

    async def _refresh_tools_once(self, *, initialize: bool = False) -> None:
        if self._client is None:
            return
        try:
            if self._catalog_token_provider is not None and not initialize:
                # Each refresh fetches with a freshly minted token: the
                # provider's credential may be short-lived (an installation
                # token lasts an hour; refreshes come every five minutes).
                await self._mint_catalog_token()
            if initialize:
                init_result = await self._client.initialize()
                self._protocol_version = init_result.get("protocolVersion")
            try:
                tools_from_upstream = await self._client.list_tools()
            except MCPSessionExpired:
                # The catalog's own session expired between refreshes. The
                # client has dropped it, so list_tools initializes a new one.
                tools_from_upstream = await self._client.list_tools()
        except Exception as exc:  # noqa: BLE001
            # ANY fetch failure marks the status, deliberately (liminal#75):
            # /healthz reads degraded until a fetch succeeds again. A stale
            # catalog on refresh serves an increasingly wrong tool surface --
            # a health check that stays green through that is the exact
            # failure mode this issue exists to kill. Only the log severity
            # is scoped: startup failure means zero tools (error); a refresh
            # failure keeps serving the last good catalog (warning).
            # COARSE ON THE WIRE, DETAIL IN THE LOG. `exc` embeds the
            # upstream's own response body for a 5xx — MCPTransportError is
            # built as f"server {status}: {resp.text[:200]}" — and routes.py
            # serves catalog_status VERBATIM on /healthz, which has no auth at
            # all. So interpolating it here let an UPSTREAM choose what liminal
            # republishes to unauthenticated callers, which is precisely what
            # `trust = "untrusted"` exists to prevent (Prudence, liminal#84 r1;
            # driven: a 500 upstream and a bare GET /healthz returned 200
            # characters of upstream body in the JSON).
            #
            # The status still discriminates the two cases a health check
            # actually needs, and the log lines below already carry the cause.
            # The "catalog fetch failed" prefix is deliberate: it keeps the
            # existing assertion in test_fail_loud.py green without editing
            # someone else's test, and the parenthetical still discriminates
            # the two cases a health check needs to tell apart.
            self.catalog_status = (
                "catalog fetch failed (startup)" if initialize
                else "catalog fetch failed (refresh)"
            )
            if initialize:
                log.error(
                    "http_target.catalog_failed",
                    target=self.name,
                    error=str(exc),
                )
            else:
                log.warning(
                    "http_target.refresh_failed",
                    target=self.name,
                    error=str(exc),
                )
            return

        raw_specs = [
            ToolSpec(
                name=t.name,
                description=t.description,
                input_schema=t.input_schema or {"type": "object", "properties": {}},
            )
            for t in tools_from_upstream
        ]
        # #16 — inspect the catalog at ingest (the single chokepoint). TRUSTED
        # targets pass through; UNTRUSTED get flag/strip/block per policy.
        #
        # GUARDED LIKE THE FETCH ABOVE (#86). This call sat outside that try,
        # so anything inspection raised went straight into the lifespan and
        # aborted startup. inspect_catalog now handles an oversized schema as
        # a finding, but the payload is upstream-authored either way, so an
        # inspection failure degrades THIS target (zero tools at startup, the
        # last inspected catalog on refresh) and /healthz says so. The status
        # is fixed text for the same reason as above: /healthz is unauthenticated.
        try:
            inspected = inspect_catalog(
                raw_specs, self.trust, self.spec.on_untrusted
            )
        except Exception as exc:  # noqa: BLE001
            self.catalog_status = (
                "catalog inspection failed (startup)" if initialize
                else "catalog inspection failed (refresh)"
            )
            log.error(
                "http_target.catalog_inspection_failed",
                target=self.name,
                error_type=type(exc).__name__,
                error=str(exc)[:200],
            )
            return
        self._tools = inspected
        self.catalog_status = "ready"
        log.info(
            "http_target.tools_refreshed",
            target=self.name,
            trust=self.trust.value,
            fetched=len(raw_specs),
            after_inspection=len(self._tools),
        )

    async def _refresh_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.spec.refresh_tools_interval_seconds)
                await self._refresh_tools_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("http_target.refresh_loop_exception", target=self.name)


def build_http_targets(
    specs: list[TargetSpec],
    *,
    reserved_names: set[str] | None = None,
) -> list[HttpTarget]:
    """Validate specs + build ``HttpTarget`` s, rejecting name collisions.

    ``reserved_names`` are names already taken (e.g. in-process registry keys);
    a target colliding with one — or with another target in ``specs`` — is a
    loud ``TargetConfigError`` (No Silent Failures).
    """
    from liminal.target.config import TargetConfigError

    reserved = set(reserved_names or ())
    seen: set[str] = set()
    targets: list[HttpTarget] = []
    for spec in specs:
        spec.validate()
        if spec.transport != "http":
            raise TargetConfigError(
                f"build_http_targets: target {spec.name!r} has transport "
                f"{spec.transport!r}; only 'http' is supported in Stage A"
            )
        if spec.name in reserved:
            raise TargetConfigError(
                f"target {spec.name!r} collides with an already-registered "
                "handler/target name"
            )
        if spec.name in seen:
            raise TargetConfigError(
                f"duplicate target name {spec.name!r} in target specs"
            )
        seen.add(spec.name)
        targets.append(HttpTarget(spec))
    return targets
