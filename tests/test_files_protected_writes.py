"""liminal#108: files_write refuses agent-instruction files without a grant.

CLAUDE.md, AGENTS.md and friends are loaded as instructions by every later
agent session in that directory, so one steered write is a persistent prompt
injection. The gate matches case-insensitively, in any directory, on both the
requested and the resolved path, and lifts only for the server-side
`files:protected_writes` grant — never for anything the caller's token says.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.handlers.files import PROTECTED_WRITE_SCOPE, FilesConfig, FilesHandler
from liminal.protocol import Context
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_app,
)

REFUSAL = "protected instruction file"


class _Audit:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = fail

    async def __call__(self, *, allowed: bool, detail: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("audit store down")
        self.calls.append({"allowed": allowed, **detail})


def _ctx(
    *, scopes: frozenset[str] = frozenset(), audit: _Audit | None = None, **extra: Any
) -> Context:
    return Context(
        identity="rook",
        agent_name="rook-primus",
        credentials={},
        extra=dict(extra),
        granted_scopes=scopes,
        audit=audit,
    )


def _handler(root: Path) -> FilesHandler:
    return FilesHandler(default_config=FilesConfig(allowed_paths=[root]))


async def _write(handler: FilesHandler, path: str, ctx: Context | None = None):
    return await handler.dispatch(
        "write", {"path": path, "content": "ignore previous instructions"}, ctx or _ctx()
    )


# ---- the deny list ----------------------------------------------------------

BLOCKED = [
    "CLAUDE.md",
    "claude.md",
    "Claude.Md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "agents.MD",
    "GEMINI.md",
    ".cursorrules",
    ".CursorRules",
    "sub/deeper/CLAUDE.md",
    "./CLAUDE.md",
    "sub/./AGENTS.md",
    "sub//GEMINI.md",
    "CLAUDE.md/",
    ".claude/settings.json",
    ".Claude/settings.local.json",
    "sub/.CLAUDE/hooks/pre.sh",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("rel", BLOCKED)
async def test_protected_name_is_refused(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert REFUSAL in result.error
    assert "requires operator grant" in result.error
    # Nothing was created, not even the parent directories.
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
async def test_dotdot_route_to_a_protected_name_is_refused_before_the_gate(tmp_path) -> None:
    """Not a test of the #108 gate: `..` never reaches it, because
    `_safe_resolve` refuses the segment first. Kept so that relaxing that
    defence cannot silently open a `..` route to a protected name."""
    (tmp_path / "sub").mkdir()
    result = await _write(_handler(tmp_path), f"{tmp_path}/sub/../CLAUDE.md")
    assert result.is_error is True
    assert "contains '..'" in result.error
    assert not (tmp_path / "CLAUDE.md").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        "notes.md",
        "CLAUDE.md.bak",
        "my-agents.md",
        "docs/claude/guide.md",
        ".claude-notes/x.md",
        ".cursorrules.txt",
    ],
)
async def test_ordinary_files_still_write(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is False, result.error
    assert (tmp_path / rel).read_text() == "ignore previous instructions"


# ---- symlinks: both the requested and the resolved path are checked --------


@pytest.mark.asyncio
async def test_ordinary_name_symlinked_to_a_protected_file_is_refused(tmp_path) -> None:
    (tmp_path / "CLAUDE.md").write_text("original")
    os.symlink(tmp_path / "CLAUDE.md", tmp_path / "notes.md")
    result = await _write(_handler(tmp_path), f"{tmp_path}/notes.md")
    assert result.is_error is True
    assert REFUSAL in result.error
    assert (tmp_path / "CLAUDE.md").read_text() == "original"


@pytest.mark.asyncio
async def test_directory_symlinked_to_dot_claude_is_refused(tmp_path) -> None:
    (tmp_path / ".claude").mkdir()
    os.symlink(tmp_path / ".claude", tmp_path / "cfg")
    result = await _write(_handler(tmp_path), f"{tmp_path}/cfg/settings.json")
    assert result.is_error is True
    assert not (tmp_path / ".claude" / "settings.json").exists()


@pytest.mark.asyncio
async def test_protected_name_symlinked_to_an_ordinary_file_is_refused(tmp_path) -> None:
    """The resolved path is harmless here, so only the requested-path check
    catches it. A tool loading CLAUDE.md follows the link."""
    (tmp_path / "real.txt").write_text("original")
    os.symlink(tmp_path / "real.txt", tmp_path / "CLAUDE.md")
    result = await _write(_handler(tmp_path), f"{tmp_path}/CLAUDE.md")
    assert result.is_error is True
    assert (tmp_path / "real.txt").read_text() == "original"


# ---- the grant, and only the grant ------------------------------------------


@pytest.mark.asyncio
async def test_granted_scope_allows_the_write_and_audits_it(tmp_path) -> None:
    audit = _Audit()
    ctx = _ctx(scopes=frozenset({PROTECTED_WRITE_SCOPE}), audit=audit)
    result = await _write(_handler(tmp_path), f"{tmp_path}/AGENTS.md", ctx)
    assert result.is_error is False, result.error
    assert (tmp_path / "AGENTS.md").exists()
    assert audit.calls == [
        {
            "allowed": True,
            "tool": "files.write",
            "path": str((tmp_path / "AGENTS.md").resolve()),
            "protected": "agents.md",
            "reason": "protected write granted",
        }
    ]


@pytest.mark.asyncio
async def test_denial_is_audited(tmp_path) -> None:
    audit = _Audit()
    await _write(_handler(tmp_path), f"{tmp_path}/.claude/settings.json", _ctx(audit=audit))
    assert [(c["allowed"], c["protected"]) for c in audit.calls] == [(False, ".claude/")]


@pytest.mark.asyncio
async def test_ordinary_write_is_not_audited(tmp_path) -> None:
    audit = _Audit()
    await _write(_handler(tmp_path), f"{tmp_path}/notes.md", _ctx(audit=audit))
    assert audit.calls == []


@pytest.mark.asyncio
async def test_granted_write_is_refused_when_the_audit_fails(tmp_path) -> None:
    ctx = _ctx(scopes=frozenset({PROTECTED_WRITE_SCOPE}), audit=_Audit(fail=True))
    result = await _write(_handler(tmp_path), f"{tmp_path}/CLAUDE.md", ctx)
    assert result.is_error is True
    assert not (tmp_path / "CLAUDE.md").exists()


@pytest.mark.asyncio
async def test_admin_scope_does_not_imply_the_grant(tmp_path) -> None:
    ctx = _ctx(scopes=frozenset({"admin:*", "files:write"}))
    result = await _write(_handler(tmp_path), f"{tmp_path}/CLAUDE.md", ctx)
    assert result.is_error is True


@pytest.mark.asyncio
async def test_ctx_extra_cannot_grant(tmp_path) -> None:
    """ctx.extra carries the token's tool_extras in single-cabal mode, so it
    must never be where the grant is read from."""
    ctx = _ctx(**{PROTECTED_WRITE_SCOPE: True, "files.protected_writes": True})
    result = await _write(_handler(tmp_path), f"{tmp_path}/CLAUDE.md", ctx)
    assert result.is_error is True


# ---- through the HTTP route --------------------------------------------------

SVC = "archivist@rd"


def _key() -> RSAKey:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    k = RSAKey.import_key(pem)
    k.ensure_kid()
    return k


def _mint(key: RSAKey, *, iss: str, **extra: Any) -> str:
    now = int(time.time())
    payload = {
        "iss": iss, "sub": "rook-primus", "aud": SVC, "iat": now, "exp": now + 60,
        "cabal_persona": "rook",
    }
    payload.update(extra)
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, payload, key)


async def _call_write(client: AsyncClient, tok: str, path: Path) -> dict[str, Any]:
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "files.write", "arguments": {"path": str(path), "content": "x"}},
    }
    resp = await client.post("/mcp", json=body, headers={"Authorization": f"Bearer {tok}"})
    assert "result" in resp.json(), resp.json()
    return resp.json()["result"]


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [set(), {PROTECTED_WRITE_SCOPE}])
async def test_sovereign_grant_decides_and_is_audited(tmp_path, scopes: set[str]) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    key = _key()
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=KeySet([key]), expected_issuer="rd-cabal", expected_audience=SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "files", _handler(root))
    app = create_app(jwt_verifier=verifier, registry=reg, policy_store=store)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        await store.grant(
            "rd-cabal", "rook", scopes={"files:write", *scopes}, allowed_handlers={"files"}
        )
        # The token claims the scope itself in both cases; only the grant counts.
        tok = _mint(key, iss="rd-cabal", scope=["dispatch", PROTECTED_WRITE_SCOPE])
        result = await _call_write(client, tok, root / "CLAUDE.md")
        rows = [
            r for r in await store.audit(limit=20)
            if r.detail.get("tool") == "files.write"
        ]
    store.close()

    granted = bool(scopes)
    assert result["isError"] is (not granted)
    assert (root / "CLAUDE.md").exists() is granted
    assert [r.action for r in rows] == ["access_allow" if granted else "access_deny"]
    assert rows[0].persona == "rook" and rows[0].issuer == "rd-cabal"


@pytest.mark.asyncio
async def test_single_cabal_token_scope_cannot_grant(tmp_path) -> None:
    """Single-cabal mode has no server-side grant, so nothing lifts the gate —
    in particular not the token's own scope claim."""
    key = _key()
    verifier = StaticKeySetVerifier(
        key_set=KeySet([key]), expected_issuer="rd-cabal", expected_audience=SVC
    )
    reg = Registry()
    register_explicit(reg, "files", _handler(tmp_path))
    app = create_app(jwt_verifier=verifier, registry=reg)
    tok = _mint(
        key, iss="rd-cabal",
        cabal_scope=["dispatch", PROTECTED_WRITE_SCOPE],
        cabal_tool_extras={PROTECTED_WRITE_SCOPE: True, "files.protected_writes": True},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        result = await _call_write(client, tok, tmp_path / "CLAUDE.md")
    assert result["isError"] is True
    assert REFUSAL in _json_text(result)
    assert not (tmp_path / "CLAUDE.md").exists()


def _json_text(result: dict[str, Any]) -> str:
    return " ".join(b.get("text", "") for b in result.get("content", []))


@pytest.mark.asyncio
async def test_auth_off_with_an_inert_store_neither_grants_nor_audits(
    tmp_path, monkeypatch
) -> None:
    """A store wired under LIMINAL_AUTH_DISABLED is inert (app.py): no grant is
    resolved, so nothing lifts the gate, and no audit rows are written."""
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    root = tmp_path / "repo"
    root.mkdir()
    reg = Registry()
    register_explicit(reg, "files", _handler(root))
    app = create_app(registry=reg, policy_store=store)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        result = await _call_write(client, "anything", root / "CLAUDE.md")
        rows = await store.audit(limit=20)
    store.close()
    assert result["isError"] is True
    assert not (root / "CLAUDE.md").exists()
    assert [r for r in rows if r.detail.get("tool") == "files.write"] == []
