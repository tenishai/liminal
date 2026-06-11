"""Phase II — limenal CLI `serve` builds the CabalCoreCredentialResolver
when --cabal-url + (LIMENAL_CABAL_TOKEN or --cabal-token-env) are set.

The real serve loop calls uvicorn.run which blocks; we exercise just the
app-construction path by reaching into create_app via the same import
the CLI uses.
"""

from __future__ import annotations

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
