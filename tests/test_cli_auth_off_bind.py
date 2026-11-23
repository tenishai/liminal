"""`liminal serve` refuses LIMINAL_AUTH_DISABLED=1 on a non-loopback bind (#214).

Goes through main() with uvicorn.run stubbed, so no server starts.
"""

from __future__ import annotations

import pytest

import liminal.cli as cli

OVERRIDE = "LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("LIMINAL_AUTH_DISABLED", OVERRIDE, "LIMINAL_JWKS_URL"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def started(monkeypatch):
    import uvicorn

    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    return calls


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "::", "192.168.1.20", "10.0.0.5", "liminal.example.com", "localhost.evil.com", ""]
)
def test_auth_off_refuses_non_loopback(monkeypatch, capsys, started, host) -> None:
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    assert cli.main(["serve", "--host", host]) == 2
    err = capsys.readouterr().err
    assert "error:" in err and OVERRIDE in err
    assert started == []


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost", "LOCALHOST"])
def test_auth_off_starts_on_loopback(monkeypatch, started, host) -> None:
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    assert cli.main(["serve", "--host", host]) == 0
    assert len(started) == 1


def test_auth_on_starts_on_0000(monkeypatch, capsys, started) -> None:
    assert cli.main(["serve", "--host", "0.0.0.0", "--jwks-url", "https://i.example/jwks.json"]) == 0
    assert len(started) == 1
    assert OVERRIDE not in capsys.readouterr().err


def test_override_starts_with_a_warning_naming_it(monkeypatch, capsys, started) -> None:
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    monkeypatch.setenv(OVERRIDE, "1")
    assert cli.main(["serve", "--host", "0.0.0.0"]) == 0
    assert len(started) == 1
    err = capsys.readouterr().err
    assert "warning:" in err and OVERRIDE in err and "loopback only" in err


def test_override_alone_does_not_turn_auth_off(monkeypatch, started) -> None:
    monkeypatch.setenv(OVERRIDE, "1")
    assert cli.main(["serve", "--host", "0.0.0.0", "--jwks-url", "https://i.example/jwks.json"]) == 0
