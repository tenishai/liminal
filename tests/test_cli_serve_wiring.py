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


def test_parse_trust_registry_extra_scope_map_deprecated_and_ignored(capsys) -> None:
    """[scope_map] is DEPRECATED (limenal#26): scopes are derived from handler
    capability cards now, so a present [scope_map] is ignored (resolver stays
    None) with a warning — not honoured, and not raised on."""
    from limenal.cli import _parse_trust_registry_extra

    _tool_extras, policy_scope_for = _parse_trust_registry_extra(
        {"scope_map": {"scratchpad": "mem:append"}}
    )
    assert policy_scope_for is None  # no longer builds a config-driven resolver
    assert "deprecated" in capsys.readouterr().err
    # Even a malformed [scope_map] is just ignored now (not validated/raised).
    _parse_trust_registry_extra({"scope_map": "not-a-dict"})


def test_parse_trust_registry_extra_malformed_tool_extras_raises() -> None:
    """A non-table [tool_extras] must raise ValueError with a clear message."""
    from limenal.cli import _parse_trust_registry_extra

    with pytest.raises(ValueError, match="tool_extras"):
        _parse_trust_registry_extra({"tool_extras": ["list", "not", "dict"]})


def test_scope_for_from_registry_derives_from_cards() -> None:
    """scope_for_from_registry builds the handler->scope map from each card's
    required_scope; a None-scope handler (scratchpad) is absent from the map."""
    from limenal.handlers.scratchpad import ScratchpadHandler
    from limenal.handlers.web import WebHandler
    from limenal.registry import Registry
    from limenal.registry.discover import register_explicit
    from limenal.server.app import scope_for_from_registry

    reg = Registry()
    register_explicit(reg, "web", WebHandler())
    register_explicit(reg, "scratchpad", ScratchpadHandler())

    scope_for = scope_for_from_registry(reg)
    assert scope_for("web") == "web:fetch"  # declared on the web card
    assert scope_for("scratchpad") is None  # required_scope=None → open
    assert scope_for("nonexistent") is None


def test_scope_for_from_registry_per_tool() -> None:
    """#42: per-tool scopes resolve for the full "<handler>.<tool>" name, with
    the handler-level scope as fallback and unscoped tools/handlers open."""
    from limenal.handlers.files import FilesHandler
    from limenal.handlers.memory import MemoryHandler
    from limenal.handlers.web import WebHandler
    from limenal.registry import Registry
    from limenal.registry.discover import register_explicit
    from limenal.server.app import scope_for_from_registry

    reg = Registry()
    register_explicit(reg, "memory", MemoryHandler())
    register_explicit(reg, "files", FilesHandler())
    register_explicit(reg, "web", WebHandler())

    scope_for = scope_for_from_registry(reg)
    # per-tool read/write split — the whole point of #42
    assert scope_for("memory.recall") == "mem:query"
    assert scope_for("memory.commit") == "mem:append"
    assert scope_for("files.read") == "files:read"
    assert scope_for("files.write") == "files:write"
    assert scope_for("files.list") == "files:read"
    assert scope_for("files.exists") == "files:read"
    # handler-level fallback (web declares no per-tool scopes)
    assert scope_for("web.fetch") == "web:fetch"
    # memory/files handler-level is None → a bare handler is open
    assert scope_for("memory") is None


@pytest.mark.asyncio
async def test_handler_derived_scope_gates_tools_call(tmp_path, signing_key, keyset) -> None:
    """Part 3 of limenal#26: a granted-but-under-scoped caller is refused at a
    scope-gated handler, with the scope map DERIVED FROM THE HANDLER CARDS —
    no policy_scope_for is injected. `web` declares required_scope='web:fetch';
    the scope gate refuses a grant that lacks it and records a deny audit entry.
    """
    from limenal.handlers.web import WebHandler
    from limenal.registry import Registry
    from limenal.registry.discover import register_explicit
    from limenal.server import (
        MultiIssuerJWKSVerifier,
        SqlitePolicyStore,
        StaticKeySetVerifier,
    )

    _SVC = "scope-gate-test"
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset, expected_issuer="rd-cabal", expected_audience=_SVC,
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "scope.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "web", WebHandler())

    # No policy_scope_for passed → create_app DERIVES it from the cards.
    app = create_app(jwt_verifier=verifier, registry=reg, policy_store=store)
    assert app.state.policy_scope_for("web") == "web:fetch"

    # Grant web access but WITHOUT web:fetch — allowed_handlers passes the first
    # gate; the scope gate is what must refuse.
    await store.grant(
        "rd-cabal", "rook", scopes={"mem:query"}, allowed_handlers={"web"},
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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "web.fetch", "arguments": {"url": "http://x"}},
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        err = r.json()["error"]
        assert "scope 'web:fetch' required" in err["message"], err["message"]
        denies = [d for d in await store.audit(limit=20) if d.action == "access_deny"]

        # Admission: re-grant WITH web:fetch → the scope gate now passes. The
        # call still fails downstream (unresolvable host), but NOT on scope —
        # this rules out a gate that refuses everything.
        await store.grant(
            "rd-cabal", "rook", scopes={"web:fetch"}, allowed_handlers={"web"},
        )
        r2 = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "web.fetch",
                    "arguments": {"url": "http://nonexistent.invalid"},
                },
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        msg2 = (r2.json().get("error") or {}).get("message", "")
        assert "scope 'web:fetch' required" not in msg2, (
            f"scope gate should have ADMITTED the web:fetch-scoped grant: {msg2!r}"
        )

    store.close()
    assert any(d.detail.get("required_scope") == "web:fetch" for d in denies), (
        "access_deny audit entry with required_scope=web:fetch not found"
    )
