"""liminal#31 — create_app's build-time config guards raise ConfigError, which
cli.main() catches at the boundary → ``error: …`` + exit 2, honouring the
"config mistakes never surface as a traceback" contract. Mirrors
test_main_returns_2_for_name_collision (the --targets path already honoured it).
"""

from __future__ import annotations

import pytest

from liminal.server import ConfigError


def test_config_error_is_runtimeerror_subclass() -> None:
    """Back-compat: any existing ``except RuntimeError`` still catches these
    guards (they raised bare RuntimeError before #31)."""
    assert issubclass(ConfigError, RuntimeError)


def test_main_exits_2_for_auth_disabled_with_verifier(monkeypatch, capsys) -> None:
    """LIMINAL_AUTH_DISABLED=1 alongside a configured verifier (--jwks-url) is a
    config mistake → clean exit 2 with a diagnostic, not an uncaught traceback.

    Fail-without-fix: pre-#31 create_app raised a bare RuntimeError that
    propagated out of main() as a traceback (main never returned 2).
    """
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    from liminal.cli import main

    rc = main(["serve", "--jwks-url", "https://issuer.example/.well-known/jwks.json"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "LIMINAL_AUTH_DISABLED" in err


def test_create_app_raises_config_error_for_auth_disabled_with_verifier(
    monkeypatch, keyset, registry
) -> None:
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    from liminal.server import StaticKeySetVerifier, create_app

    with pytest.raises(ConfigError, match="LIMINAL_AUTH_DISABLED"):
        create_app(jwt_verifier=StaticKeySetVerifier(key_set=keyset), registry=registry)


def test_create_app_raises_config_error_for_multi_issuer_without_policy_store(
    keyset, registry
) -> None:
    from liminal.server import (
        MultiIssuerJWKSVerifier,
        StaticKeySetVerifier,
        create_app,
    )

    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset, expected_issuer="rd-cabal", expected_audience="svc"
            )
        },
        parents=frozenset({"rd-cabal"}),
    )
    with pytest.raises(ConfigError, match="MultiIssuerJWKSVerifier requires"):
        create_app(jwt_verifier=verifier, registry=registry, policy_store=None)
