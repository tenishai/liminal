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
            if r.detail.get("tool") == "files.write" and r.detail.get("kind") != "call"
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
    assert [r for r in rows if r.detail.get("tool") == "files.write" and r.detail.get("kind") != "call"] == []


# ---- code-execution paths (#110) --------------------------------------------

EXEC_REFUSAL = "protected code-execution path"

EXEC_BLOCKED = [
    ".git/hooks/pre-commit",
    ".git/hooks/post-checkout",
    ".GIT/Hooks/pre-push",
    "sub/repo/.git/hooks/pre-commit",
    ".git/hooks/sub/x",
    "./.git/hooks/pre-commit",
    "sub//.git/hooks/pre-commit",
    ".git/config",
    ".git/modules/s/hooks/x",
    ".git/modules/s/config",
    ".git/worktrees/w/commondir",
    ".git/info/attributes",
    ".git/worktrees/w/config.worktree",
    "sub/.git/hooks/x",
    ".mcp.json",
    ".MCP.JSON",
    "sub/deeper/.mcp.json",
    ".claude.json",
    ".Claude.Json",
    "sub/.claude.json",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("rel", EXEC_BLOCKED)
async def test_code_execution_path_is_refused(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert EXEC_REFUSAL in result.error
    assert "requires operator grant" in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("rel", [".windsurfrules", ".clinerules", ".cursor/rules/x.mdc",
                                 ".cursor/mcp.json", ".github/copilot-instructions.md",
                                 ".GitHub/Copilot-Instructions.md"])
async def test_other_tools_instruction_files_are_refused(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert REFUSAL in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        ".github/hooks.md",
        ".github/workflows/ci.yml",
        "docs/hooks/guide.md",
        "hooks/pre-commit",
        ".git-notes/hooks/x",
        ".gitignore",
        ".gitattributes",
        "sub/.gitattributes",
        ".gitconfig",
        ".gitmodules",
        ".github/hooks/x",
        "mcp.json",
        ".mcp.json.bak",
        "claude.json",
    ],
)
async def test_neighbours_of_code_execution_paths_still_write(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is False, result.error
    assert (tmp_path / rel).read_text() == "ignore previous instructions"


@pytest.mark.asyncio
async def test_git_pointer_file_at_a_worktree_root_is_refused(tmp_path) -> None:
    """In a linked worktree or submodule checkout `.git` is a file holding
    `gitdir: <path>`; rewriting it redirects git to an attacker's gitdir."""
    (tmp_path / ".git").write_text("gitdir: /real/gitdir\n")
    result = await _write(_handler(tmp_path), f"{tmp_path}/.git")
    assert result.is_error is True
    assert EXEC_REFUSAL in result.error
    assert (tmp_path / ".git").read_text() == "gitdir: /real/gitdir\n"
    result = await _write(_handler(tmp_path), f"{tmp_path}/sub/.git")
    assert result.is_error is True
    assert EXEC_REFUSAL in result.error


@pytest.mark.asyncio
async def test_symlink_into_git_hooks_is_refused(tmp_path) -> None:
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    os.symlink(tmp_path / ".git" / "hooks", tmp_path / "h")
    result = await _write(_handler(tmp_path), f"{tmp_path}/h/pre-commit")
    assert result.is_error is True
    assert EXEC_REFUSAL in result.error
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()


@pytest.mark.asyncio
async def test_ordinary_name_symlinked_to_mcp_json_is_refused(tmp_path) -> None:
    (tmp_path / ".mcp.json").write_text("{}")
    os.symlink(tmp_path / ".mcp.json", tmp_path / "notes.json")
    result = await _write(_handler(tmp_path), f"{tmp_path}/notes.json")
    assert result.is_error is True
    assert (tmp_path / ".mcp.json").read_text() == "{}"


@pytest.mark.asyncio
async def test_granted_scope_lifts_the_code_execution_gate(tmp_path) -> None:
    audit = _Audit()
    ctx = _ctx(scopes=frozenset({PROTECTED_WRITE_SCOPE}), audit=audit)
    result = await _write(_handler(tmp_path), f"{tmp_path}/.mcp.json", ctx)
    assert result.is_error is False, result.error
    assert [(c["allowed"], c["protected"]) for c in audit.calls] == [(True, ".mcp.json")]


# ---- #110: more instruction files, hard links, operator patterns ------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        ".github/instructions/py.instructions.md",
        ".github/instructions/sub/x.instructions.md",
        ".clinerules/style.md",
        ".cline/rules/style.md",
        ".windsurf/rules/x.md",
        ".devin/rules/x.md",
        ".roorules",
        ".roorules-code",
        ".roo/rules/x.md",
        "sub/.Roo/rules-dev/x.md",
    ],
)
async def test_more_instruction_files_are_refused(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert REFUSAL in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel", [".gemini/settings.json", ".gemini/commands/x.toml", ".vscode/mcp.json",
            "sub/.VSCode/MCP.json"]
)
async def test_more_code_execution_paths_are_refused(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert EXEC_REFUSAL in result.error
    assert [p for p in tmp_path.rglob("*")] == []


# ---- #155 tier 1: developer tools that run code with no command ------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        ".envrc",
        "sub/.EnvRC",
        ".vscode/tasks.json",
        "sub/.VSCode/Tasks.JSON",
        ".pre-commit-config.yaml",
        "sub/.Pre-Commit-Config.yaml",
        "lefthook.yml",
        "lefthook.yaml",
        ".lefthook.yml",
        "lefthook.toml",
        "lefthook.json",
        ".lefthook.jsonc",
        "lefthook-local.yml",
        ".lefthook-local.yaml",
        ".config/lefthook.yml",
        ".husky/pre-commit",
        ".husky/_/husky.sh",
        "sub/.Husky/pre-push",
    ],
)
async def test_developer_tool_autorun_paths_are_refused(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert EXEC_REFUSAL in result.error
    assert "requires operator grant" in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        ".envrc.example",
        "envrc",
        ".vscode/launch.json",
        "vscode/tasks.json",
        "tasks.json",
        ".pre-commit-hooks.yaml",
        "pre-commit-config.yaml",
        "lefthook.md",
        "docs/lefthook/guide.md",
        "husky/pre-commit",
        ".husky-notes/x",
    ],
)
async def test_neighbours_of_developer_tool_paths_still_write(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is False, result.error
    assert (tmp_path / rel).read_text() == "ignore previous instructions"


@pytest.mark.asyncio
async def test_granted_scope_lifts_the_developer_tool_gate(tmp_path) -> None:
    audit = _Audit()
    ctx = _ctx(scopes=frozenset({PROTECTED_WRITE_SCOPE}), audit=audit)
    result = await _write(_handler(tmp_path), f"{tmp_path}/.husky/pre-commit", ctx)
    assert result.is_error is False, result.error
    assert [(c["allowed"], c["protected"]) for c in audit.calls] == [(True, ".husky/")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        ".github/instructions.md",
        ".github/instructions",
        ".github/ISSUE_TEMPLATE/bug.md",
        ".cline/notes.md",
        ".windsurf/notes.md",
        ".devin/notes.md",
        "rules/x.md",
        ".vscode/settings.json",
        "vscode/mcp.json",
        "roorules",
        ".roorules.bak",
        "gemini/settings.json",
    ],
)
async def test_neighbours_of_the_new_paths_still_write(tmp_path, rel: str) -> None:
    result = await _write(_handler(tmp_path), f"{tmp_path}/{rel}")
    assert result.is_error is False, result.error
    assert (tmp_path / rel).read_text() == "ignore previous instructions"


HARD_LINK_REFUSAL = "protected hard-linked file"


@pytest.mark.asyncio
async def test_hard_link_to_a_protected_file_is_refused(tmp_path) -> None:
    """The case name matching cannot see: an ordinary name sharing an inode
    with CLAUDE.md."""
    (tmp_path / "CLAUDE.md").write_text("be careful")
    os.link(tmp_path / "CLAUDE.md", tmp_path / "notes.md")
    result = await _write(_handler(tmp_path), f"{tmp_path}/notes.md")
    assert result.is_error is True
    assert HARD_LINK_REFUSAL in result.error
    assert "requires operator grant" in result.error
    assert (tmp_path / "CLAUDE.md").read_text() == "be careful"


@pytest.mark.asyncio
async def test_hard_link_to_a_protected_file_outside_the_allowlist_is_refused(
    tmp_path,
) -> None:
    """The protected file may be somewhere the handler never looks, like
    ~/.claude.json, which is why the rule is "any hard link"."""
    outside = tmp_path / "home"
    root = tmp_path / "repo"
    outside.mkdir()
    root.mkdir()
    (outside / ".claude.json").write_text("{}")
    os.link(outside / ".claude.json", root / "config.json")
    result = await _write(_handler(root), f"{root}/config.json")
    assert result.is_error is True
    assert HARD_LINK_REFUSAL in result.error
    assert (outside / ".claude.json").read_text() == "{}"


@pytest.mark.asyncio
async def test_hard_link_between_ordinary_files_is_refused_too(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    os.link(tmp_path / "a.txt", tmp_path / "b.txt")
    result = await _write(_handler(tmp_path), f"{tmp_path}/b.txt")
    assert result.is_error is True
    assert HARD_LINK_REFUSAL in result.error


@pytest.mark.asyncio
async def test_singly_linked_file_is_overwritten(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a much longer original text")
    result = await _write(_handler(tmp_path), f"{tmp_path}/a.txt")
    assert result.is_error is False, result.error
    assert (tmp_path / "a.txt").read_text() == "ignore previous instructions"


@pytest.mark.asyncio
async def test_hard_link_denial_is_audited_and_grant_lifts_it(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    os.link(tmp_path / "a.txt", tmp_path / "b.txt")
    audit = _Audit()
    await _write(_handler(tmp_path), f"{tmp_path}/b.txt", _ctx(audit=audit))
    granted = _ctx(scopes=frozenset({PROTECTED_WRITE_SCOPE}), audit=audit)
    result = await _write(_handler(tmp_path), f"{tmp_path}/b.txt", granted)
    assert result.is_error is False, result.error
    assert (tmp_path / "a.txt").read_text() == "ignore previous instructions"
    assert [(c["allowed"], c["protected"]) for c in audit.calls] == [
        (False, "hard link"),
        (True, "hard link"),
    ]


@pytest.mark.asyncio
async def test_hard_link_made_between_the_gate_and_the_open_is_refused(
    tmp_path, monkeypatch
) -> None:
    """The write re-checks the link count on the open file, so a link made
    between the gate's stat and that fstat does not get through. A link made
    after the fstat, while the write runs, is not caught; nothing tests that
    because nothing prevents it."""
    import liminal.handlers.files as files_mod

    (tmp_path / "CLAUDE.md").write_text("be careful")
    (tmp_path / "notes.md").write_text("n")
    real = files_mod._is_hard_linked

    def gate_check_then_link(path: Path) -> bool:
        answer = real(path)
        (tmp_path / "notes.md").unlink()
        os.link(tmp_path / "CLAUDE.md", tmp_path / "notes.md")
        return answer

    monkeypatch.setattr(files_mod, "_is_hard_linked", gate_check_then_link)
    result = await _write(_handler(tmp_path), f"{tmp_path}/notes.md")
    assert result.is_error is True
    assert "became a hard-linked file" in result.error
    assert (tmp_path / "CLAUDE.md").read_text() == "be careful"


# ---- operator patterns (LIMINAL_FILES_PROTECTED_PATTERNS) -------------------

OPERATOR_REFUSAL = "protected operator-protected path"


def _patterned(root: Path, *patterns: str) -> FilesHandler:
    return FilesHandler(
        default_config=FilesConfig(allowed_paths=[root], protected_patterns=list(patterns))
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("pattern", "rel"),
    [
        (".myhooks", ".myhooks/pre-commit"),
        (".myhooks/", "sub/.myhooks/pre-commit"),
        ("*.env", "config/prod.env"),
        ("*.ENV", "Prod.Env"),
        (".githooks/*", ".githooks/pre-push"),
        (".githooks/*", "sub/.githooks/deep/x"),
        ("Makefile", "Makefile"),
    ],
)
async def test_operator_pattern_is_refused(tmp_path, pattern: str, rel: str) -> None:
    result = await _write(_patterned(tmp_path, pattern), f"{tmp_path}/{rel}")
    assert result.is_error is True
    assert OPERATOR_REFUSAL in result.error
    assert f"operator pattern {pattern.casefold().rstrip('/')}" in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
async def test_operator_pattern_can_be_an_absolute_path(tmp_path) -> None:
    pattern = f"{tmp_path.resolve().as_posix()}/locked/*"
    handler = _patterned(tmp_path, pattern)
    result = await _write(handler, f"{tmp_path}/locked/a.txt")
    assert result.is_error is True
    assert OPERATOR_REFUSAL in result.error
    ok = await _write(handler, f"{tmp_path}/open/a.txt")
    assert ok.is_error is False, ok.error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("pattern", "rel"),
    [
        (".myhooks", "myhooks/pre-commit"),
        ("*.env", "prod.env.example"),
        (".githooks/*", "my.githooks/x"),
        ("Makefile", "Makefile.am"),
    ],
)
async def test_operator_pattern_neighbours_still_write(tmp_path, pattern: str, rel: str) -> None:
    result = await _write(_patterned(tmp_path, pattern), f"{tmp_path}/{rel}")
    assert result.is_error is False, result.error


@pytest.mark.asyncio
async def test_operator_patterns_add_to_and_never_replace_the_builtins(tmp_path) -> None:
    """Built-ins are checked first, and there is no syntax to remove one: a
    pattern that matches nothing, or a negation-looking one, leaves them on."""
    handler = _patterned(tmp_path, "nothing-matches-this", "!CLAUDE.md", "")
    for rel in ["CLAUDE.md", ".mcp.json", ".git/hooks/pre-commit"]:
        result = await _write(handler, f"{tmp_path}/{rel}")
        assert result.is_error is True, rel
        assert "operator pattern" not in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
async def test_operator_pattern_matches_through_a_symlinked_parent(tmp_path) -> None:
    (tmp_path / ".myhooks").mkdir()
    os.symlink(tmp_path / ".myhooks", tmp_path / "h")
    result = await _write(_patterned(tmp_path, ".myhooks"), f"{tmp_path}/h/pre-commit")
    assert result.is_error is True
    assert OPERATOR_REFUSAL in result.error
    assert not (tmp_path / ".myhooks" / "pre-commit").exists()


@pytest.mark.asyncio
async def test_operator_patterns_apply_under_a_per_persona_allowlist(tmp_path) -> None:
    """A JWT-narrowed allowlist builds its own config; the patterns still come
    from the operator's, and nothing in ctx.extra can drop them."""
    handler = _patterned(tmp_path, ".myhooks")
    ctx = _ctx(**{"files.allowed_paths": [str(tmp_path)], "files.protected_patterns": []})
    result = await _write(handler, f"{tmp_path}/.myhooks/pre-commit", ctx)
    assert result.is_error is True
    assert OPERATOR_REFUSAL in result.error


@pytest.mark.asyncio
async def test_grant_lifts_an_operator_pattern_and_is_audited(tmp_path) -> None:
    audit = _Audit()
    ctx = _ctx(scopes=frozenset({PROTECTED_WRITE_SCOPE}), audit=audit)
    result = await _write(_patterned(tmp_path, ".myhooks"), f"{tmp_path}/.myhooks/x", ctx)
    assert result.is_error is False, result.error
    assert [(c["allowed"], c["protected"]) for c in audit.calls] == [
        (True, "operator pattern .myhooks")
    ]


def _fresh_handler(monkeypatch, value: str | None):
    """get_handler() memoises, so reset the singleton before each read."""
    import liminal.handlers.files as files_mod

    monkeypatch.setattr(files_mod, "_SINGLETON", None)
    if value is None:
        monkeypatch.delenv(files_mod.PROTECTED_PATTERNS_ENV, raising=False)
    else:
        monkeypatch.setenv(files_mod.PROTECTED_PATTERNS_ENV, value)
    return files_mod.get_handler()


def test_unset_pattern_env_adds_nothing(monkeypatch) -> None:
    assert _fresh_handler(monkeypatch, None).default_config.protected_patterns == []


def test_pattern_env_is_split_on_pathsep_and_normalised(monkeypatch) -> None:
    raw = os.pathsep.join([" .MyHooks/ ", "", "*.env", "  "])
    handler = _fresh_handler(monkeypatch, raw)
    assert handler.default_config.protected_patterns == [".myhooks", "*.env"]


@pytest.mark.asyncio
async def test_pattern_env_refuses_end_to_end(monkeypatch, tmp_path) -> None:
    """Both variables set, no JWT: the auth-off deployment the env vars serve."""
    import liminal.handlers.files as files_mod

    monkeypatch.setenv(files_mod.ALLOWED_PATHS_ENV, str(tmp_path))
    handler = _fresh_handler(monkeypatch, ".myhooks")
    result = await _write(handler, f"{tmp_path}/.myhooks/pre-commit")
    assert result.is_error is True
    assert OPERATOR_REFUSAL in result.error
    ok = await _write(handler, f"{tmp_path}/notes.md")
    assert ok.is_error is False, ok.error


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern", ["sub/.myhooks/", "sub/.myhooks"])
async def test_operator_path_pattern_protects_files_beneath_it(tmp_path, pattern: str) -> None:
    """A path pattern naming a directory, with or without the trailing `/`,
    covers what is under it, not only the directory's own path."""
    handler = _patterned(tmp_path, pattern)
    for rel in ["sub/.myhooks/pre-commit", "x/sub/.myhooks/deep/hook", "sub/.myhooks"]:
        result = await _write(handler, f"{tmp_path}/{rel}")
        assert result.is_error is True, rel
        assert OPERATOR_REFUSAL in result.error
    assert [p for p in tmp_path.rglob("*")] == []
    for rel in ["sub/.myhooks-notes/x", "other/.myhooks/x", "sub/myhooks/x"]:
        ok = await _write(handler, f"{tmp_path}/{rel}")
        assert ok.is_error is False, (rel, ok.error)


@pytest.mark.asyncio
async def test_operator_absolute_dir_pattern_protects_files_beneath_it(tmp_path) -> None:
    pattern = f"{tmp_path.resolve().as_posix()}/locked/"
    handler = _patterned(tmp_path, pattern)
    for rel in ["locked/a.txt", "locked/deep/b.txt"]:
        result = await _write(handler, f"{tmp_path}/{rel}")
        assert result.is_error is True, rel
        assert OPERATOR_REFUSAL in result.error
    ok = await _write(handler, f"{tmp_path}/locked-not/a.txt")
    assert ok.is_error is False, ok.error


@pytest.mark.asyncio
async def test_operator_root_pattern_protects_the_whole_tree(tmp_path) -> None:
    """`/` keeps its slash through normalisation; its beneath form must be
    `/*`, not `//*`, or it would protect only the root path itself."""
    handler = _patterned(tmp_path, "/")
    for rel in ["a.txt", "deep/b.txt"]:
        result = await _write(handler, f"{tmp_path}/{rel}")
        assert result.is_error is True, rel
        assert OPERATOR_REFUSAL in result.error
    assert [p for p in tmp_path.rglob("*")] == []


# ---- the documented tier-2 recipe (#155) -------------------------------------


def _documented_recipe() -> str:
    """The pattern string docs/running.md tells operators to set, read from the
    doc itself so the doc and this test cannot drift apart."""
    doc = (Path(__file__).resolve().parents[1] / "docs" / "running.md").read_text()
    after = doc.split("<!-- recipe:tier2", 1)[1]
    line = next(ln for ln in after.splitlines() if ln.startswith("LIMINAL_FILES_PROTECTED_PATTERNS="))
    return line.split("=", 1)[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rel",
    [
        "conftest.py", "tests/conftest.py", "pytest.ini", "tox.ini", "noxfile.py",
        "setup.py", "setup.cfg", "pyproject.toml", "web/package.json",
        "Makefile", "GNUmakefile", "sub/makefile", "justfile",
    ],
)
async def test_documented_recipe_refuses_build_and_test_files(monkeypatch, tmp_path, rel: str) -> None:
    import liminal.handlers.files as files_mod

    recipe = _documented_recipe().replace(":", os.pathsep)
    monkeypatch.setenv(files_mod.ALLOWED_PATHS_ENV, str(tmp_path))
    result = await _write(_fresh_handler(monkeypatch, recipe), f"{tmp_path}/{rel}")
    assert result.is_error is True, rel
    assert OPERATOR_REFUSAL in result.error
    assert [p for p in tmp_path.rglob("*")] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("rel", ["src/app.py", "tests/test_x.py", "Makefile.am", "package-lock.json", "README.md"])
async def test_documented_recipe_leaves_ordinary_files_writable(monkeypatch, tmp_path, rel: str) -> None:
    import liminal.handlers.files as files_mod

    recipe = _documented_recipe().replace(":", os.pathsep)
    monkeypatch.setenv(files_mod.ALLOWED_PATHS_ENV, str(tmp_path))
    result = await _write(_fresh_handler(monkeypatch, recipe), f"{tmp_path}/{rel}")
    assert result.is_error is False, (rel, result.error)
