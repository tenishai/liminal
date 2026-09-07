"""Per-tool scope enforcement for federated (HttpTarget) tools — liminal#78.

liminal#42 made per-tool scopes real for in-process handlers by deriving them
from each ``CapabilityCard``. Federated tools have no card, so they resolved to
``None`` and a persona granted a target got every tool on it. #78 closes that
with an operator-authored scope map on ``TargetSpec``.

The scope map is operator-authored ON PURPOSE — see ``TargetSpec.tool_scopes``.
``test_scopes_are_not_read_from_the_upstream_catalog`` is the guard for that.
"""

from __future__ import annotations

import pathlib
import time

import pytest
from httpx import ASGITransport, AsyncClient
from joserfc import jwt

from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_app,
)
from liminal.server.app import DENY_SCOPE, scope_for
from liminal.target.config import TargetConfigError, TargetSpec


def _spec(name: str, **kw) -> TargetSpec:
    return TargetSpec(name=name, address=f"https://{name}.invalid/mcp", **kw)


# ---- resolver ------------------------------------------------------------


def test_target_level_scope_applies_to_every_tool() -> None:
    """A target-level required_scope gates all of that target's tools — the
    federated analogue of CapabilityCard.required_scope."""
    resolver = scope_for(Registry(), [_spec("jira", required_scope="jira:use")])
    assert resolver("jira") == "jira:use"
    assert resolver("jira.create_issue") == "jira:use"
    assert resolver("jira.anything_at_all") == "jira:use"


def test_per_tool_scope_refines_the_target_level_one() -> None:
    """Per-tool rules win over the target-level rule, so a read/write split is
    expressible for a federated target just like it is for a handler (#42)."""
    resolver = scope_for(
        Registry(),
        [
            _spec(
                "jira",
                required_scope="jira:use",
                tool_scopes={"search": "jira:read", "create_issue": "jira:write"},
            )
        ],
    )
    assert resolver("jira.search") == "jira:read"
    assert resolver("jira.create_issue") == "jira:write"
    # Unnamed tool falls back to the target-level rule, not to open.
    assert resolver("jira.transition") == "jira:use"


def test_declaring_tool_scopes_makes_a_target_deny_by_default() -> None:
    """#78's deny-by-default: with tool_scopes declared and NO target-level
    scope, a tool nobody named resolves to an unsatisfiable scope.

    This is the property that matters on catalog refresh — a tool that appears
    in a later upstream catalog must not arrive pre-authorized.
    """
    resolver = scope_for(Registry(), [_spec("jira", tool_scopes={"search": "jira:read"})])
    assert resolver("jira.search") == "jira:read"
    assert resolver("jira.newly_appeared_tool") == DENY_SCOPE
    assert resolver("jira") == DENY_SCOPE


def test_a_target_with_no_scope_rules_stays_open() -> None:
    """Deny-by-default is opt-in. A target declaring neither rule resolves to
    None (open), preserving today's behavior for existing deployments — the
    operator's allowed_handlers grant is still the primary gate."""
    resolver = scope_for(Registry(), [_spec("jira")])
    assert resolver("jira") is None
    assert resolver("jira.search") is None


def test_handler_and_target_maps_coexist() -> None:
    """Both sources key the same "<target>.<tool>" namespace and must not
    interfere — create_app already forbids name collisions between them."""
    from liminal.handlers.files import FilesHandler

    reg = Registry()
    register_explicit(reg, "files", FilesHandler())
    resolver = scope_for(reg, [_spec("jira", tool_scopes={"search": "jira:read"})])

    assert resolver("files.read") == "files:read"  # card-derived, unchanged
    assert resolver("files.write") == "files:write"
    assert resolver("jira.search") == "jira:read"  # target-derived
    assert resolver("jira.other") == DENY_SCOPE
    # A handler is NOT made deny-by-default by an unrelated strict target.
    assert resolver("files.exists") == "files:read"


def test_scope_for_from_registry_is_unchanged_without_targets() -> None:
    """The #26/#42 entry point keeps its exact behavior — no target, no deny."""
    from liminal.handlers.web import WebHandler
    from liminal.server.app import scope_for_from_registry

    reg = Registry()
    register_explicit(reg, "web", WebHandler())
    resolver = scope_for_from_registry(reg)
    assert resolver("web") == "web:fetch"
    assert resolver("nonexistent") is None
    assert resolver("nonexistent.tool") is None


def test_scopes_are_not_read_from_the_upstream_catalog() -> None:
    """The security property behind the design: nothing an UNTRUSTED upstream
    puts in its catalog can influence the scope map.

    An upstream that could declare its own required scopes would declare that
    its most dangerous tool needs none. TargetSpec is operator config, so the
    only inputs here are operator-authored — asserted by resolving a tool name
    the operator never named on a strict target.
    """
    spec = _spec("evil", tool_scopes={"safe_tool": "evil:read"})
    resolver = scope_for(Registry(), [spec])
    # An upstream adding "exfiltrate" to its catalog cannot make it callable.
    assert resolver("evil.exfiltrate") == DENY_SCOPE


# ---- config validation ---------------------------------------------------


def test_tool_scopes_must_be_a_table_of_non_empty_strings() -> None:
    with pytest.raises(TargetConfigError, match="must be a table"):
        _spec("jira", tool_scopes="not-a-table").validate()
    with pytest.raises(TargetConfigError, match="non-empty scope string"):
        _spec("jira", tool_scopes={"search": ""}).validate()
    with pytest.raises(TargetConfigError, match="empty/non-string"):
        _spec("jira", tool_scopes={"": "jira:read"}).validate()
    with pytest.raises(TargetConfigError, match="required_scope"):
        _spec("jira", required_scope="  ").validate()


def test_tool_scopes_load_from_toml_tables() -> None:
    """The [[target]] loader accepts the new keys (and still rejects typos)."""
    from liminal.target.config import load_target_specs

    specs = load_target_specs(
        [
            {
                "name": "jira",
                "address": "https://jira.invalid/mcp",
                "required_scope": "jira:use",
                "tool_scopes": {"search": "jira:read"},
            }
        ]
    )
    assert specs[0].required_scope == "jira:use"
    assert specs[0].tool_scopes == {"search": "jira:read"}

    with pytest.raises(TargetConfigError, match="unknown key"):
        load_target_specs(
            [{"name": "j", "address": "https://x/mcp", "tool_scope": {"a": "b"}}]
        )


# ---- end to end ----------------------------------------------------------


@pytest.mark.asyncio
async def test_federated_tool_is_scope_gated_at_tools_call(
    tmp_path, signing_key, keyset
) -> None:
    """The gate is load-bearing over HTTP, not just in the resolver.

    A persona granted the whole `jira` target is still refused the specific
    tool it lacks the scope for — which is exactly what #78 reported was
    impossible. The admission half then proves the gate is not refusing
    everything.
    """
    _SVC = "federated-scope-test"
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset, expected_issuer="rd-cabal", expected_audience=_SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "fed-scope.db"), parent_issuer="rd-cabal")

    app = create_app(
        jwt_verifier=verifier,
        registry=Registry(),
        policy_store=store,
        targets=[
            _spec(
                "jira",
                tool_scopes={"search": "jira:read", "create_issue": "jira:write"},
            )
        ],
    )
    # Derived without an injected policy_scope_for.
    assert app.state.policy_scope_for("jira.create_issue") == "jira:write"

    # The whole target is granted; only the write scope is missing.
    await store.grant(
        "rd-cabal", "rook", scopes={"jira:read"}, allowed_handlers={"jira"}
    )

    now = int(time.time())
    tok = jwt.encode(
        {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"},
        {
            "iss": "rd-cabal", "sub": "rook-primus", "aud": _SVC,
            "iat": now, "exp": now + 60, "cabal_persona": "rook",
        },
        signing_key,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def call(tool: str, rpc_id: int) -> str:
            r = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                    "params": {"name": tool, "arguments": {}},
                },
                headers={"Authorization": f"Bearer {tok}"},
            )
            return (r.json().get("error") or {}).get("message", "")

        assert "scope 'jira:write' required" in await call("jira.create_issue", 1)

        # Deny-by-default reaches the wire for an unnamed tool. The message
        # names the fix rather than the sentinel — see
        # test_sentinel_refusal_does_not_tell_the_operator_to_grant_it.
        assert "not named in the scope map" in await call("jira.undeclared", 2)

        # Admission: the read-scoped tool is NOT refused on scope. It fails
        # downstream (the target was never started), which is the point — the
        # gate admitted it.
        admitted = await call("jira.search", 3)
        assert "required" not in admitted, f"scope gate should have admitted: {admitted!r}"

    denies = [d for d in await store.audit(limit=20) if d.action == "access_deny"]
    store.close()
    assert any(d.detail.get("required_scope") == "jira:write" for d in denies), (
        "no access_deny audit row recorded for the federated scope refusal"
    )


def test_required_scope_shadows_deny_by_default() -> None:
    """Prudence, #81 round 1. The documented example was the config where the
    documented claim is FALSE.

    Precedence is exact -> target-level -> sentinel, so a target-level
    `required_scope` shadows the sentinel and an unnamed tool falls back to it.
    Declaring both therefore turns deny-by-default OFF. This test exists so the
    doc and the code cannot drift apart again.
    """
    both = scope_for(
        Registry(),
        [_spec("jira", required_scope="jira:use", tool_scopes={"search": "jira:read"})],
    )
    assert both("jira.NEW_UPSTREAM_TOOL") == "jira:use"  # NOT the sentinel
    assert both("jira.NEW_UPSTREAM_TOOL") != DENY_SCOPE

    only_tool_scopes = scope_for(
        Registry(), [_spec("jira", tool_scopes={"search": "jira:read"})]
    )
    assert only_tool_scopes("jira.NEW_UPSTREAM_TOOL") == DENY_SCOPE


@pytest.mark.asyncio
async def test_sentinel_refusal_does_not_tell_the_operator_to_grant_it(
    tmp_path, signing_key, keyset
) -> None:
    """Prudence, #81 round 1. `scope 'liminal:deny' required` read as an
    instruction — and granting it works, silently disabling the gate on every
    strict target. The refusal must name the fix, not the sentinel."""
    _SVC = "sentinel-msg-test"
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset, expected_issuer="rd-cabal", expected_audience=_SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "msg.db"), parent_issuer="rd-cabal")
    app = create_app(
        jwt_verifier=verifier,
        registry=Registry(),
        policy_store=store,
        targets=[_spec("jira", tool_scopes={"search": "jira:read"})],
    )
    await store.grant(
        "rd-cabal", "rook", scopes={"jira:read"}, allowed_handlers={"jira"}
    )
    now = int(time.time())
    tok = jwt.encode(
        {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"},
        {"iss": "rd-cabal", "sub": "rook-primus", "aud": _SVC,
         "iat": now, "exp": now + 60, "cabal_persona": "rook"},
        signing_key,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "jira.undeclared", "arguments": {}}},
            headers={"Authorization": f"Bearer {tok}"},
        )
    store.close()
    msg = (r.json().get("error") or {}).get("message", "")
    assert "not named in the scope map" in msg
    assert "tool_scopes" in msg
    # It may warn against granting the sentinel, but must never read as
    # "you need scope X" where X is the sentinel.
    assert f"scope {DENY_SCOPE!r} required" not in msg
    assert "Do NOT grant" in msg


def test_required_scope_rejects_non_strings_instead_of_failing_open() -> None:
    """Prudence, #81 r2. `str(...)` coercion in the validator let every
    non-string through, and the falsy ones — 0, False, [], {}, all valid TOML —
    were then silently DROPPED by `if spec.required_scope:` in app.py, leaving a
    target with no tool_scopes wholly open. A fail-open, not a symmetry nit."""
    for bad in (0, False, [], {}, 12.5):
        with pytest.raises(TargetConfigError, match="must be a string"):
            _spec("jira", required_scope=bad).validate()


def test_a_dropped_required_scope_would_leave_the_target_open() -> None:
    """The consequence the validator now prevents, pinned directly: had a falsy
    non-string reached the resolver, the target would resolve to None — open —
    rather than to its intended scope."""
    good = scope_for(Registry(), [_spec("jira", required_scope="jira:use")])
    assert good("jira.anything") == "jira:use"
    # And the config that would have produced the open state is refused above,
    # so the resolver can never see it.
    with pytest.raises(TargetConfigError):
        _spec("jira", required_scope=0).validate()


@pytest.mark.asyncio
async def test_audit_row_does_not_record_the_sentinel_as_a_required_scope(
    tmp_path, signing_key, keyset
) -> None:
    """Prudence, #81 r2. The round-2 fix rewrote the wire message but left the
    audit row recording required_scope='liminal:deny'. The same rationale —
    naming the sentinel reads as an instruction to grant it — applies to a
    structured field an operator greps while triaging a denial."""
    _SVC = "audit-sentinel-test"
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset, expected_issuer="rd-cabal", expected_audience=_SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "aud.db"), parent_issuer="rd-cabal")
    app = create_app(
        jwt_verifier=verifier, registry=Registry(), policy_store=store,
        targets=[_spec("jira", tool_scopes={"search": "jira:read"})],
    )
    await store.grant(
        "rd-cabal", "rook", scopes={"jira:read"}, allowed_handlers={"jira"}
    )
    now = int(time.time())
    tok = jwt.encode(
        {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"},
        {"iss": "rd-cabal", "sub": "rook-primus", "aud": _SVC,
         "iat": now, "exp": now + 60, "cabal_persona": "rook"},
        signing_key,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "jira.undeclared", "arguments": {}}},
            headers={"Authorization": f"Bearer {tok}"},
        )
    denies = [d for d in await store.audit(limit=20) if d.action == "access_deny"]
    store.close()
    assert denies, "no deny audit row recorded"
    row = denies[-1].detail
    assert row.get("required_scope") != DENY_SCOPE, (
        "the audit row still names the sentinel as a required scope"
    )
    assert row.get("deny_reason") == "not-in-scope-map"


def test_the_documented_targets_toml_actually_loads() -> None:
    """Prudence, #81 r2. The doc example shipped TWO `[[target]]` tables named
    "jira", so `build_http_targets` refused the documented file with
    `duplicate target name`. An operator copying design.md got a config that
    would not start. This parses the fenced TOML out of the doc and loads it,
    so the example cannot silently rot again.
    """
    import tomllib

    from liminal.target import build_http_targets
    from liminal.target.config import load_target_specs

    doc = (
        pathlib.Path(__file__).resolve().parents[1] / "docs" / "design.md"
    ).read_text()
    # design.md has several ```toml blocks (a pyproject example among them);
    # take every one that declares targets and load them ALL, since the
    # collision is BETWEEN blocks a reader would put in one file.
    blocks = [
        b.split("```", 1)[0]
        for b in doc.split("```toml")[1:]
        if "[[target]]" in b.split("```", 1)[0]
    ]
    assert blocks, "no [[target]] example found in docs/design.md"
    raw: list[dict] = []
    for b in blocks:
        raw.extend(tomllib.loads(b).get("target", []))
    specs = load_target_specs(raw)
    assert specs, "no [[target]] tables found in the documented example"
    # The real collision check lives here, not in the loader.
    build_http_targets(specs, reserved_names=set())
    names = [s.name for s in specs]
    assert len(names) == len(set(names)), f"duplicate target names in docs: {names}"
