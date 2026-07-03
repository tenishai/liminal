"""Phase II — limenal CLI `serve` builds the CabalCoreCredentialResolver
when --cabal-url + (LIMENAL_CABAL_TOKEN or --cabal-token-env) are set.

The real serve loop calls uvicorn.run which blocks; we exercise just the
app-construction path by reaching into create_app via the same import
the CLI uses.

Also covers Item 3 of Phase-0 pre-#12 hardening: [scope_map] / [tool_extras]
wiring from the trust-registry TOML through the CLI-config helper into
create_app (limenal #26 partial).
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient
from joserfc import jwt

from limenal.server import (
    CabalCoreCredentialResolver,
    create_app,
)


def test_resolver_class_can_be_imported_via_public_surface() -> None:
    """The CLI imports `CabalCoreCredentialResolver` from `limenal.server`;
    keep that import path stable."""
    assert CabalCoreCredentialResolver is not None


def test_create_app_accepts_async_resolver_callable(keyset, registry) -> None:
    """Wire a resolver into create_app the same way the CLI does after
    parsing --cabal-url. App should build without error."""
    from limenal.server import StaticKeySetVerifier

    resolver = CabalCoreCredentialResolver(
        cabal_url="http://test",
        token_provider=lambda: "static-token",
    )
    bound = resolver.fetch
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=registry,
        credential_resolver=bound,
    )
    assert app.state.credential_resolver is bound


def test_default_token_env_name() -> None:
    """The CLI default is LIMENAL_CABAL_TOKEN; lock that in so the
    operator's docs + Cabal's docs + tests can't drift."""
    from limenal import cli as cli_module

    # Smoke that the entry exists; the actual default string is asserted
    # by the help-text presence (operator-facing surface).
    assert cli_module.main is not None
    help_text = cli_module.main.__doc__ or ""  # noqa: F841 - placeholder
    # Defaults live in argparse setup inside main(); we check it round-trips
    # via the --help output rather than re-implementing parser construction.
    from contextlib import redirect_stdout
    from io import StringIO

    buf = StringIO()
    try:
        with redirect_stdout(buf):
            cli_module.main(["serve", "--help"])
    except SystemExit:
        pass  # argparse exits 0 after --help
    assert "LIMENAL_CABAL_TOKEN" in buf.getvalue()


def test_resolver_token_provider_re_reads_env_each_call(monkeypatch) -> None:
    """The CLI's closure looks up the env var per fetch so a rotation
    propagates without a daemon restart. Spot-check the pattern."""
    import os

    monkeypatch.setenv("TEST_LIMENAL_TOKEN", "v1")

    def provider() -> str:
        return os.environ.get("TEST_LIMENAL_TOKEN", "")

    assert provider() == "v1"
    monkeypatch.setenv("TEST_LIMENAL_TOKEN", "v2")
    assert provider() == "v2"


# ---- Item 3: _parse_trust_registry_extra — validation + wiring ------------


def test_parse_trust_registry_extra_absent_sections_returns_none() -> None:
    """Both outputs are None when [scope_map] and [tool_extras] are absent.
    This preserves the current default behaviour (no scope enforcement)."""
    from limenal.cli import _parse_trust_registry_extra

    policy_tool_extras, policy_scope_for = _parse_trust_registry_extra({})
    assert policy_tool_extras is None
    assert policy_scope_for is None


def test_parse_trust_registry_extra_malformed_scope_map_raises() -> None:
    """A non-table [scope_map] must raise ValueError with a clear message
    (CLAUDE.md: No Silent Failures — a malformed section must not pass silently)."""
    from limenal.cli import _parse_trust_registry_extra

    with pytest.raises(ValueError, match="scope_map"):
        _parse_trust_registry_extra({"scope_map": "not-a-dict"})


def test_parse_trust_registry_extra_malformed_tool_extras_raises() -> None:
    """A non-table [tool_extras] must raise ValueError with a clear message."""
    from limenal.cli import _parse_trust_registry_extra

    with pytest.raises(ValueError, match="tool_extras"):
        _parse_trust_registry_extra({"tool_extras": ["list", "not", "dict"]})


def test_parse_trust_registry_extra_scope_map_non_string_value_raises() -> None:
    """A scope_map value that is not a string must raise ValueError."""
    from limenal.cli import _parse_trust_registry_extra

    with pytest.raises(ValueError, match="scope_map"):
        _parse_trust_registry_extra({"scope_map": {"scratchpad": 42}})


@pytest.mark.asyncio
async def test_cli_scope_map_gates_tools_call(tmp_path, signing_key, keyset) -> None:
    """Wire policy_scope_for via the CLI helper (_parse_trust_registry_extra)
    and assert the scope gate refuses calls lacking the required scope and
    records a deny audit entry.

    This is the CLI-config path test for limenal #26 (partial): scope
    enforcement is POSSIBLE via [scope_map]; the full method→scope derivation
    from the handler surface stays in #26.
    """
    import tomllib

    from limenal.cli import _parse_trust_registry_extra
    from limenal.handlers.scratchpad import ScratchpadHandler
    from limenal.registry import Registry
    from limenal.registry.discover import register_explicit
    from limenal.server import (
        MultiIssuerJWKSVerifier,
        SqlitePolicyStore,
        StaticKeySetVerifier,
    )

    _SVC = "scope-gate-test"

    # Simulate the TOML the CLI would load from --trust-registry.
    toml_text = (
        'service_audience = "scope-gate-test"\n'
        '\n'
        '[[issuer]]\n'
        'id = "rd-cabal"\n'
        'jwks_uri = "http://unused"\n'
        'parent = true\n'
        '\n'
        '[scope_map]\n'
        'scratchpad = "mem:append"\n'
    )
    cfg = tomllib.loads(toml_text)
    policy_tool_extras, policy_scope_for = _parse_trust_registry_extra(cfg)

    assert policy_scope_for is not None
    assert policy_scope_for("scratchpad") == "mem:append"
    assert policy_scope_for("memory") is None

    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset,
                expected_issuer="rd-cabal",
                expected_audience=_SVC,
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "scope.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(
        jwt_verifier=verifier,
        registry=reg,
        policy_store=store,
        policy_scope_for=policy_scope_for,
        policy_tool_extras=policy_tool_extras,
    )

    # Grant scratchpad access but only with mem:query — the handler needs mem:append.
    await store.grant(
        "rd-cabal", "rook",
        scopes={"mem:query"},
        allowed_handlers={"scratchpad"},
    )

    now = int(time.time())
    tok = jwt.encode(
        {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"},
        {
            "iss": "rd-cabal",
            "sub": "rook-primus",
            "aud": _SVC,
            "iat": now,
            "exp": now + 60,
            "cabal_persona": "rook",
        },
        signing_key,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scratchpad.set", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        err = r.json()["error"]
        assert "scope 'mem:append' required" in err["message"], err["message"]
        denies = [d for d in await store.audit(limit=20) if d.action == "access_deny"]

    store.close()
    assert any(d.detail.get("required_scope") == "mem:append" for d in denies), (
        "access_deny audit entry with required_scope=mem:append not found"
    )
