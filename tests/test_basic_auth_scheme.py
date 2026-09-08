"""auth_scheme="basic" + bearer_token_env: upstreams that authenticate
service accounts as Basic base64(user:secret) -- Atlassian's hosted MCP is
the motivating case -- and credentials that live in env, never in a config
file that gets reviewed and baked into images.

The encoding rule lives in exactly two places (client _auth_header, target
_authorization) and both are pinned here to the same vector.
"""

from __future__ import annotations

import base64

import pytest

from liminal.client.mcp import _auth_header
from liminal.target.config import TargetConfigError, load_target_specs
from liminal.target.http import _authorization

B64 = base64.b64encode(b"svc@example.com:tok123").decode()


def test_client_header_basic_encodes_user_secret():
    assert _auth_header("svc@example.com:tok123", "basic") == {
        "Authorization": f"Basic {B64}"
    }


def test_client_header_bearer_unchanged_and_empty_still_omitted():
    assert _auth_header("tok", "bearer") == {"Authorization": "Bearer tok"}
    assert _auth_header("", "basic") == {}


def test_target_authorization_mirrors_the_client_rule():
    assert _authorization("basic", "svc@example.com:tok123") == f"Basic {B64}"
    assert _authorization("bearer", "tok") == "Bearer tok"


def test_config_accepts_env_sourced_basic_target():
    (spec,) = load_target_specs([{
        "name": "atlassian",
        "transport": "http",
        "address": "https://mcp.example.com/v1/mcp",
        "auth_method": "bearer",
        "auth_scheme": "basic",
        "bearer_token_env": "ATLASSIAN_BASIC",
        "required_scope": "atlassian:read",
    }])
    assert spec.auth_scheme == "basic"
    assert spec.bearer_token_env == "ATLASSIAN_BASIC"


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"auth_scheme": "digest"}, "auth_scheme"),
        ({"auth_scheme": "basic", "auth_method": "none"}, "needs a credential"),
        (
            {"bearer_token": "x", "bearer_token_env": "Y"},
            "mutually exclusive",
        ),
        ({"bearer_token": None, "bearer_token_env": None}, "requires"),
    ],
)
def test_config_rejects_incoherent_auth(overrides, fragment):
    base = {
        "name": "t",
        "transport": "http",
        "address": "https://x/mcp",
        "auth_method": "bearer",
        "bearer_token": "tok",
    }
    raw = {**base, **overrides}
    raw = {k: v for k, v in raw.items() if v is not None}
    with pytest.raises(TargetConfigError, match=fragment):
        load_target_specs([raw])


def test_startup_reads_the_env_and_refuses_an_empty_var(monkeypatch):
    import asyncio

    from liminal.target.config import TargetSpec
    from liminal.target.http import HttpTarget

    spec = TargetSpec(
        name="atlassian",
        address="https://mcp.example.com/v1/mcp",
        auth_method="bearer",
        auth_scheme="basic",
        bearer_token_env="ATLASSIAN_BASIC",
    )
    spec.validate()
    monkeypatch.delenv("ATLASSIAN_BASIC", raising=False)
    target = HttpTarget(spec)
    with pytest.raises(RuntimeError, match="ATLASSIAN_BASIC"):
        asyncio.run(target.startup())
