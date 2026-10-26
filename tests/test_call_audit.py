"""Every call that reaches a handler leaves one audit row beside the denials,
and the audit endpoint filters by persona and agent (per-agent activity, 2026-10-25)."""
from __future__ import annotations

import pytest

from liminal.server.routes import summarize_args
from tests.test_policy_inversion import _hdr, _mint, _rpc, sov  # noqa: F401


def test_arguments_are_summarized_and_secrets_masked():
    line = summarize_args({"url": "https://x/" + "a" * 100, "api_key": "sk-123", "body": {"a": 1}, "n": 3})
    assert line.startswith("api_key=*** body=<dict of 1> n=3 url=https://x/aaa")
    assert "sk-123" not in line and line.endswith("...") and len(line) <= 300
    assert summarize_args({}) == "" and summarize_args("nope") == ""


@pytest.mark.asyncio
async def test_an_allowed_call_leaves_one_row_and_the_endpoint_filters_by_agent(sov) -> None:  # noqa: F811
    client, kp, ks, _store = sov
    ptok = _mint(kp, iss="rd-cabal")
    await client.post(
        "/admin/policy/grant",
        json={"issuer": "shaz-cabal", "persona": "rook", "scopes": ["scratchpad:use"], "allowed_handlers": ["scratchpad"]},
        headers=_hdr(ptok),
    )
    tok = _mint(ks, iss="shaz-cabal")
    body = (await _rpc(client, tok, "tools/call", {"name": "scratchpad.set", "arguments": {"key": "k", "value": "v", "token": "s3cret"}})).json()
    assert "result" in body, body
    rows = (await client.get("/admin/policy/audit?agent=rook-primus", headers=_hdr(ptok))).json()["audit"]
    calls = [r for r in rows if r["action"] == "access_allow"]
    assert len(calls) == 1
    d = calls[0]["detail"]
    assert d["handler"] == "scratchpad" and d["tool"] == "scratchpad.set" and d["outcome"] == "ok"
    assert d["args"] == "key=k token=*** value=v" and isinstance(d["ms"], int)
    assert calls[0]["persona"] == "rook" and calls[0]["agent"] == "rook-primus"
    other = (await client.get("/admin/policy/audit?agent=nobody", headers=_hdr(ptok))).json()["audit"]
    assert other == []
    by_persona = (await client.get("/admin/policy/audit?persona=rook", headers=_hdr(ptok))).json()["audit"]
    assert any(r["action"] == "access_allow" for r in by_persona)
