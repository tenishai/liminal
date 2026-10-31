"""Stateful streamable-HTTP upstreams: ``session = "per-persona"`` (liminal#172).

The upstream here behaves like the one that motivated the issue: it returns an
``Mcp-Session-Id`` on ``initialize`` and refuses every later request without
one, with the error a real server sent (``-32600 Request must be an initialize
request if no session ID is provided``). A session it doesn't know gets 404,
the streamable-HTTP spec's "that session is gone".

The cross-persona tests seed each persona with a recognisable sentinel
credential and assert the other persona's sentinel and session id never
appear on its requests (liminal#93's negative, for the one per-persona state
liminal now keeps).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

import httpx
import pytest

from liminal.client.mcp import SESSION_HEADER, AsyncMCPClient, MCPSessionExpired
from liminal.protocol import Context
from liminal.target.config import TargetConfigError, TargetSpec, load_target_specs
from liminal.target.http import HttpTarget

ALICE_SECRET = "ALICE-SENTINEL-do-not-cross"
BOB_SECRET = "BOB-SENTINEL-do-not-cross"


@dataclass
class Seen:
    method: str | None
    session: str | None
    auth: str | None
    headers: dict[str, str]


@dataclass
class StatefulUpstream:
    """An MCP server that keeps sessions. ``stateless=True`` issues none and
    requires none, like an ordinary server."""

    stateless: bool = False
    # Forget every persona session right after issuing it (the catalog's,
    # sess-1, survives): each call then meets a 404.
    forget_persona_sessions: bool = False
    # Lose the persona session once, the way Datadog's hosted server does: a
    # JSON-RPC error "missing session ID" (HTTP 200) instead of the spec's 404
    # (liminal#224). The session is forgotten, so a reopened one works.
    lose_persona_sessions_as_rpc_error: int = 0  # how many calls in a row meet it
    rpc_losses: int = 0
    sessions: dict[str, str | None] = field(default_factory=dict)  # sid -> opening auth
    seen: list[Seen] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    issued: int = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        sid = request.headers.get(SESSION_HEADER)
        auth = request.headers.get("authorization")
        if request.method == "DELETE":
            self.deleted.append(sid or "")
            self.sessions.pop(sid or "", None)
            return httpx.Response(200)
        body = json.loads(request.read())
        method, rid = body.get("method"), body.get("id")
        self.seen.append(Seen(method, sid, auth, dict(request.headers)))
        if method == "initialize":
            headers = {}
            if not self.stateless:
                self.issued += 1
                new = f"sess-{self.issued}"
                self.sessions[new] = auth
                headers[SESSION_HEADER] = new
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "stateful", "version": "1"}}
            return httpx.Response(
                200, headers=headers, json={"jsonrpc": "2.0", "id": rid, "result": result}
            )
        if self.forget_persona_sessions:
            self.sessions = {k: v for k, v in self.sessions.items() if k == "sess-1"}
        if (method == "tools/call" and sid and sid != "sess-1"
                and self.rpc_losses < self.lose_persona_sessions_as_rpc_error):
            self.rpc_losses += 1
            self.sessions.pop(sid, None)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid,
                                             "error": {"code": 0, "message": "missing session ID"}})
        if not self.stateless:
            if sid is None:
                return httpx.Response(400, json={
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32600, "message": "Request must be an initialize "
                              "request if no session ID is provided."},
                })
            if sid not in self.sessions:
                return httpx.Response(404)
        if rid is None:
            return httpx.Response(202)
        if method == "tools/list":
            result = {"tools": [{"name": "search", "inputSchema": {"type": "object"}}]}
        else:
            result = {"content": [{"type": "text", "text": f"hit via {sid}"}]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})

    def calls(self, method: str = "tools/call") -> list[Seen]:
        return [s for s in self.seen if s.method == method]


def _spec(**over) -> TargetSpec:
    base = dict(
        name="vendor", address="https://vendor.example", trust="trusted",
        auth_method="service-token", credential_key="VENDOR",
        refresh_tools_interval_seconds=0, session="per-persona",
    )
    base.update(over)
    spec = TargetSpec(**base)
    spec.validate()
    return spec


def _ctx(identity: str, secret: str, issuer: str = "https://cabal.example") -> Context:
    return Context(identity=identity, agent_name=identity,
                   credentials={"VENDOR": secret}, issuer=issuer)


async def _started(upstream: StatefulUpstream, **over) -> tuple[HttpTarget, httpx.AsyncClient]:
    async def handler(request: httpx.Request) -> httpx.Response:
        # Yield like a real network round trip, so concurrent dispatches
        # interleave instead of running one after another.
        await asyncio.sleep(0.001)
        return upstream(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    target = HttpTarget(_spec(**over), http_client=http)
    await target.startup()
    return target, http


async def _stop(target: HttpTarget, http: httpx.AsyncClient) -> None:
    await target.shutdown()
    await http.aclose()


# ---- the reported failure, and the fix --------------------------------------


async def test_without_a_session_the_catalog_fetch_fails_as_reported():
    upstream = StatefulUpstream()
    target, http = await _started(upstream, session="none")
    try:
        assert target.catalog_status == "catalog fetch failed (startup)"
        assert await target.list_tools() == []
    finally:
        await _stop(target, http)
    assert all(s.session is None for s in upstream.seen)


async def test_per_persona_catalog_fetch_lists_tools():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        assert target.catalog_status == "ready"
        assert [t.name for t in await target.list_tools()] == ["search"]
    finally:
        await _stop(target, http)
    [listed] = upstream.calls("tools/list")
    assert listed.session == "sess-1"


# ---- one session per persona, never shared ---------------------------------


async def test_each_persona_calls_inside_its_own_session():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        for ctx in (_ctx("alice", ALICE_SECRET), _ctx("bob", BOB_SECRET),
                    _ctx("alice", ALICE_SECRET)):
            result = await target.dispatch("search", {}, ctx)
            assert result.is_error is False, result.error
    finally:
        await _stop(target, http)

    catalog_sid = upstream.calls("tools/list")[0].session
    by_auth: dict[str | None, set[str | None]] = {}
    for s in upstream.calls():
        by_auth.setdefault(s.auth, set()).add(s.session)
    alice_sids = by_auth[f"Bearer {ALICE_SECRET}"]
    bob_sids = by_auth[f"Bearer {BOB_SECRET}"]
    assert len(alice_sids) == 1 and len(bob_sids) == 1
    assert alice_sids.isdisjoint(bob_sids)
    assert catalog_sid not in alice_sids | bob_sids


async def test_a_session_is_opened_with_its_own_personas_credential():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
        await target.dispatch("search", {}, _ctx("bob", BOB_SECRET))
        opened = dict(upstream.sessions)
    finally:
        await _stop(target, http)
    # sess-1 is the catalog's, opened with no persona credential (service-token).
    assert opened == {
        "sess-1": None,
        "sess-2": f"Bearer {ALICE_SECRET}",
        "sess-3": f"Bearer {BOB_SECRET}",
    }


async def test_alice_sentinel_never_rides_bobs_requests_and_back():
    """Named for what must not leak. Every request made for one persona is
    searched, headers and all, for the other persona's credential and session."""
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        await asyncio.gather(
            *(target.dispatch("search", {}, _ctx(name, secret))
              for name, secret in [("alice", ALICE_SECRET), ("bob", BOB_SECRET)] * 5)
        )
    finally:
        await _stop(target, http)

    def owner(s: Seen) -> str | None:
        blob = json.dumps(s.headers)
        return "alice" if ALICE_SECRET in blob else "bob" if BOB_SECRET in blob else None

    sid_owner: dict[str, str] = {}
    for s in upstream.seen:
        who = owner(s)
        blob = json.dumps(s.headers)
        assert not (ALICE_SECRET in blob and BOB_SECRET in blob), s
        if who and s.session:
            assert sid_owner.setdefault(s.session, who) == who, (
                f"session {s.session} carried both personas' credentials"
            )
    assert set(sid_owner.values()) == {"alice", "bob"}


async def test_same_identity_from_another_issuer_gets_another_session():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET, issuer="https://a"))
        await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET, issuer="https://b"))
    finally:
        await _stop(target, http)
    assert len({s.session for s in upstream.calls()}) == 2


async def test_concurrent_first_calls_open_one_session():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        results = await asyncio.gather(
            *(target.dispatch("search", {}, _ctx("alice", ALICE_SECRET)) for _ in range(5))
        )
    finally:
        await _stop(target, http)
    assert all(r.is_error is False for r in results)
    assert len(upstream.calls("initialize")) == 2  # catalog + alice


# ---- expiry ----------------------------------------------------------------


async def test_an_expired_session_is_reopened_once():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
        first = upstream.calls()[-1].session
        upstream.sessions.pop(first or "")  # the upstream forgot it
        result = await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
    finally:
        await _stop(target, http)
    assert result.is_error is False
    second = upstream.calls()[-1].session
    assert second != first
    assert [s.session for s in upstream.calls()] == [first, first, second]


async def test_a_second_404_is_an_error_not_a_loop():
    upstream = StatefulUpstream(forget_persona_sessions=True)
    target, http = await _started(upstream)
    try:
        result = await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
    finally:
        await _stop(target, http)
    assert result.is_error is True
    assert "transport error" in (result.error or "")
    assert len(upstream.calls()) == 2


async def test_catalog_refresh_reopens_its_expired_session():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    try:
        upstream.sessions.pop("sess-1")
        await target._refresh_tools_once()
        assert target.catalog_status == "ready"
    finally:
        await _stop(target, http)
    assert [s.session for s in upstream.calls("tools/list")] == ["sess-1", "sess-1", "sess-2"]


def test_client_drops_only_the_session_it_sent():
    client = AsyncMCPClient("https://x", token_provider=lambda: "", use_session=True)
    client._session_id, client._initialized = "new", True
    gone = client._expired("old", httpx.Response(404))
    assert isinstance(gone, MCPSessionExpired)
    assert (client._session_id, client.initialized) == ("new", True)
    client._expired("new", httpx.Response(404))
    assert (client._session_id, client.initialized) == (None, False)
    assert client._expired(None, httpx.Response(404)) is None


# ---- lifecycle and the stateless default -----------------------------------


async def test_shutdown_ends_every_session():
    upstream = StatefulUpstream()
    target, http = await _started(upstream)
    await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
    await target.dispatch("search", {}, _ctx("bob", BOB_SECRET))
    await _stop(target, http)
    assert sorted(upstream.deleted) == ["sess-1", "sess-2", "sess-3"]


async def test_per_persona_against_a_stateless_server_still_works():
    upstream = StatefulUpstream(stateless=True)
    target, http = await _started(upstream)
    try:
        result = await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
    finally:
        await _stop(target, http)
    assert result.is_error is False
    assert all(s.session is None for s in upstream.seen)
    assert upstream.deleted == []


async def test_default_sends_no_session_id_and_shares_one_client():
    upstream = StatefulUpstream(stateless=True)
    target, http = await _started(upstream, session="none")
    try:
        await target.dispatch("search", {}, _ctx("alice", ALICE_SECRET))
        await target.dispatch("search", {}, _ctx("bob", BOB_SECRET))
        assert target._sessions == {}
    finally:
        await _stop(target, http)
    assert len(upstream.calls("initialize")) == 1


# ---- config ----------------------------------------------------------------


def test_session_defaults_to_none_and_loads_from_toml_tables():
    assert TargetSpec(name="t", address="https://x").session == "none"
    [spec] = load_target_specs([{"name": "t", "address": "https://x", "session": "per-persona"}])
    assert spec.session == "per-persona"


@pytest.mark.parametrize("over, fragment", [
    ({"session": "shared"}, "session 'shared' must be one of"),
    ({"transport": "stdio", "address": "", "command": ("srv",), "session": "per-persona"},
     "session applies to http targets only"),
])
def test_bad_session_config_is_refused(over, fragment):
    spec = TargetSpec(**{"name": "t", "address": "https://x", **over})
    with pytest.raises(TargetConfigError, match=fragment):
        spec.validate()


# ---- a lost session told as a JSON-RPC error (liminal#224) --------------------


async def test_a_session_lost_as_an_rpc_error_is_reopened_once():
    """Datadog's hosted server answers a call on a session it no longer holds
    with a JSON-RPC error "missing session ID" (HTTP 200), not the spec's 404.
    The persona's client forgets the session, reopens one, and the call goes
    through; the model never sees the loss."""
    upstream = StatefulUpstream(lose_persona_sessions_as_rpc_error=1)
    target, http = await _started(upstream)
    try:
        result = await target.dispatch("search", {}, _ctx("alice", "tok-a"))
        assert result.is_error is False, result.error
        inits = [s for s in upstream.calls("initialize") if s.session is None]
        assert len(inits) == 3, "catalog, alice's first session, alice's reopened session"
        calls = upstream.calls()
        assert [c.session for c in calls][-1] == "sess-3", calls
        assert upstream.rpc_losses == 1
    finally:
        await _stop(target, http)


async def test_a_second_rpc_loss_is_an_error_not_a_loop():
    upstream = StatefulUpstream(lose_persona_sessions_as_rpc_error=2)
    target, http = await _started(upstream)
    try:
        result = await target.dispatch("search", {}, _ctx("alice", "tok-a"))
        assert result.is_error is True and "returned error [0]" in (result.error or "")
        assert len([s for s in upstream.calls("initialize") if s.session is None]) == 3, "one reopen, no more"
    finally:
        await _stop(target, http)
