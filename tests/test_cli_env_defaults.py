"""`liminal serve` takes its single-cabal knobs from LIMINAL_* env when the
flags are absent (2026-10-04): a container image bakes its CMD once, and a
deployment platform that renders the Deployment has env but no argv. The
flag still wins over the env var.

Pinned through the same seam the config-error test uses: uvicorn.run is
stubbed, and LIMINAL_AUTH_DISABLED=1 next to a verifier makes create_app
refuse with a message naming the env var — proof the env-supplied
--jwks-url reached the parser as if typed.
"""

from __future__ import annotations

import importlib


def _parser():
    import liminal.cli as cli

    importlib.reload(cli)  # defaults are read when the parser is built
    return cli


def test_env_supplies_the_single_cabal_flags(monkeypatch) -> None:
    monkeypatch.setenv("LIMINAL_JWKS_URL", "http://cabal/.well-known/jwks.json")
    monkeypatch.setenv("LIMINAL_CABAL_URL", "http://cabal")
    monkeypatch.setenv("LIMINAL_AUDIENCE", "liminal-dev")
    monkeypatch.setenv("LIMINAL_ISSUER", "cabal-dev")
    monkeypatch.setenv("LIMINAL_TARGETS", "/etc/liminal/targets.toml")
    cli = _parser()
    args = _serve_args(cli, [])
    assert args.jwks_url == "http://cabal/.well-known/jwks.json"
    assert args.cabal_url == "http://cabal"
    assert args.audience == "liminal-dev"
    assert args.issuer == "cabal-dev"
    assert args.targets == "/etc/liminal/targets.toml"


def test_the_flag_wins_over_the_env(monkeypatch) -> None:
    monkeypatch.setenv("LIMINAL_JWKS_URL", "http://from-env/jwks.json")
    monkeypatch.setenv("LIMINAL_AUDIENCE", "from-env")
    cli = _parser()
    args = _serve_args(cli, ["--jwks-url", "http://from-flag/jwks.json", "--audience", "from-flag"])
    assert args.jwks_url == "http://from-flag/jwks.json"
    assert args.audience == "from-flag"


def test_unset_and_empty_env_keep_the_old_defaults(monkeypatch) -> None:
    for name in ("LIMINAL_JWKS_URL", "LIMINAL_CABAL_URL", "LIMINAL_TARGETS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LIMINAL_ISSUER", "")  # empty means unset, not ""
    monkeypatch.setenv("LIMINAL_AUDIENCE", "")
    cli = _parser()
    args = _serve_args(cli, [])
    assert args.jwks_url is None and args.cabal_url is None and args.targets is None
    assert args.issuer == "cabal-core" and args.audience == "liminal"


def test_env_jwks_url_reaches_main_like_a_typed_flag(monkeypatch, capsys) -> None:
    """End to end through main(): with LIMINAL_AUTH_DISABLED=1 and a JWKS URL
    from env, create_app refuses exactly as it does for the typed flag."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    monkeypatch.setenv("LIMINAL_JWKS_URL", "https://issuer.example/.well-known/jwks.json")
    cli = _parser()
    assert cli.main(["serve"]) == 2
    assert "LIMINAL_AUTH_DISABLED" in capsys.readouterr().err


def _serve_args(cli, extra: list[str]):
    """Parse `serve …` with the real parser without starting the server."""
    import argparse

    captured = {}
    real = argparse.ArgumentParser.parse_args

    def spy(self, argv=None, namespace=None):
        ns = real(self, argv, namespace)
        captured["ns"] = ns
        raise SystemExit(0)  # stop main() before it serves

    try:
        argparse.ArgumentParser.parse_args = spy
        try:
            cli.main(["serve", *extra])
        except SystemExit:
            pass
    finally:
        argparse.ArgumentParser.parse_args = real
    return captured["ns"]
