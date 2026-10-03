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


def _write_registry(tmp_path, issuers: str):
    path = tmp_path / "registry.toml"
    path.write_text('service_audience = "svc"\n' + issuers)
    return str(path)


@pytest.mark.parametrize(
    "issuers",
    [
        pytest.param(
            '[[issuer]]\nid = "a"\njwks_uri = "https://a.example/jwks.json"\n',
            id="no-parent",
        ),
        pytest.param(
            '[[issuer]]\nid = "a"\njwks_uri = "https://a.example/jwks.json"\nparent = true\n'
            'admin_personas = ["op"]\n'
            '[[issuer]]\nid = "b"\njwks_uri = "https://b.example/jwks.json"\nparent = true\n',
            id="two-parents",
        ),
    ],
)
def test_main_exits_2_when_registry_parent_count_is_wrong(
    monkeypatch, capsys, tmp_path, issuers
) -> None:
    """liminal#144: a trust registry that names no parent (or several) is a
    registry mistake -> exit 2 with a diagnostic, not a traceback.

    Fail-without-fix: build_multi_issuer_verifier's ValueError propagated out
    of main() uncaught.
    """
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.delenv("LIMINAL_AUTH_DISABLED", raising=False)
    from liminal.cli import main

    registry = _write_registry(tmp_path, issuers)
    rc = main(
        ["serve", "--trust-registry", registry, "--policy-db", str(tmp_path / "p.db")]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "error: trust registry" in err
    assert "parent issuer required" in err


@pytest.mark.parametrize(
    ("env", "expect_warning"),
    [(None, True), ("1", False)],
    ids=["auth-on", "auth-disabled"],
)
def test_no_verifier_warning_only_when_auth_enabled(
    monkeypatch, capsys, env, expect_warning
) -> None:
    """With no verifier, the 'will reject every request' warning is true only
    when auth is on; under LIMINAL_AUTH_DISABLED=1 requests are accepted with
    synthesised claims, so the warning must not print."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    if env is None:
        monkeypatch.delenv("LIMINAL_AUTH_DISABLED", raising=False)
    else:
        monkeypatch.setenv("LIMINAL_AUTH_DISABLED", env)
    from liminal.cli import main

    assert main(["serve"]) == 0
    err = capsys.readouterr().err
    assert ("will reject every request" in err) is expect_warning
