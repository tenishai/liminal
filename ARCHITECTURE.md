---
card: repo-card:liminal
updated: 2026-10-03
anchor: pyproject.toml sha=8b1aa2fb1f51d78beabece0bf9cc7f569204b9d9
anchor: src/liminal/server/routes.py sha=221458c82d66576e9fd29841fe1739cf32e43c19
---
# liminal — repo card

WHAT: MCP gateway. One MCP-over-HTTP connection per agent; many backends behind it (in-process handlers discovered by entry point, plus federated HTTP MCP upstreams), with JWT auth, per-caller handler allowlists, and (sovereign mode) a server-side policy store. Renamed from `limenal` 2026-08; older issues and docs say limenal. The PyPI-style distribution name is `tenishai-liminal` (pyproject `name`; `liminal.__version__` reads it); the import package and CLI stay `liminal`.
STATE: main, v0.2.0 (pyproject), classifier Pre-Alpha, AGPL-3.0-or-later. CHANGELOG.md has an [Unreleased] section. Active area: federation hardening (multi-issuer trust, policy/admin plane, untrusted-target framing, #108/#110 protected writes, operator-only tools, SSE responses in the client #129/#131). Tags cut by hand; bump pyproject in a PR, tag THAT merge commit (tests/test_version_tags.py; v0.2.0 once shipped reporting 0.1.0, #95).
STACK: Python >=3.12, FastAPI + uvicorn, pydantic v2, joserfc (RS256 JWT), httpx, structlog, stdlib sqlite3 (policy DB only). Optional extra `[memory]` = `techne>=0.18.0` (not on a public index; pair with requirements-sources.txt, which pins the git tag; tests/test_techne_pin.py fails if pyproject, requirements-sources.txt and the Dockerfile's TECHNE_VERSION disagree). Dockerfile present. `pip install -e ".[dev]"`.
ENTRY:
- CLI `liminal` → src/liminal/cli.py:main (`version`, `list-handlers [--cards]`, `serve`)
- server factory → src/liminal/server/app.py:create_app (data plane) + create_admin_app (admin plane on `--admin-port`)
- JSON-RPC route → src/liminal/server/routes.py (POST /mcp: initialize/ping/tools/list/tools/call; GET /healthz)
- client lib → src/liminal/client/ (AsyncMCPClient/MCPClient read plain-JSON and Streamable-HTTP SSE replies; LibraryLiminalClient, ProxyLiminalClient, from_config)
AUTH MODES (exclusive, cli.py): `--jwks-url` = single-cabal (token's `cabal_scope`/`scope` must contain `dispatch`; token `cabal_tool_extras`/`tool_extras` trusted) | `--trust-registry` + `--policy-db` = sovereign (multi-issuer; token scope/extras IGNORED, grant resolved server-side) | `LIMINAL_AUTH_DISABLED=1` = synthesized claims (identity `anonymous`, scope `[dispatch]`, issuer `local`) and NO JWT verification. With no grant and no token claims, the grant-based scope gate is skipped and the handler allowlist finds no `tool_extras` to restrict by (all handlers allowed). Still applied: the secret guard (routes.py; off only via `LIMINAL_SECRET_GUARD`, not by auth-disabled) and the operator-only gate, which refuses every `requires_operator` tool because no caller can prove operator scope. `--jwks-url` and `--trust-registry` together = CLI error exit 2.
REQUEST PATH (routes.py:_handle_tools_call): auth → handler allowlist → per-tool scope gate (sovereign only) → operator-only gate (`requires_operator` tools, EVERY mode) → secret guard (write tools) → credential resolver → build Context → Multiplexer.dispatch → wire framing (+ `_meta["liminal/untrusted"]` for untrusted targets).

SEAMS → card:
- handler-protocol  src/liminal/protocol/handler.py + registry/discover.py  (entry-point Handler contract; cabal ships handlers through it)  → docs/arch/handler-protocol.md
- policy            src/liminal/server/policy.py + routes.py + admin.py  (sovereign authz: grants, parent rows, audit)  → docs/arch/policy.md
- credentials       src/liminal/server/credentials.py  (per-(persona,handler) secrets from cabal /admin/secrets)  → docs/arch/credentials.md
- targets           src/liminal/dispatch/multiplexer.py + target/*  (namespacing, federated HTTP upstreams, untrusted framing)  → docs/arch/targets.md
- client            src/liminal/client/mcp.py + library.py  (MCP client lib cabal imports)  → docs/arch/client.md
- (uncarded) server/secret_guard.py: shape-based pre-dispatch scan of files.write/memory.commit/notify.send content; fail-closed, ON unless `LIMINAL_SECRET_GUARD` is falsey.
- (uncarded) server/auth.py: JWTVerifier Protocol; URLJWKSVerifier (RS256 pin, iss/aud/exp/iat, needs `cabal_persona`|`persona` AND `sub`), MultiIssuerJWKSVerifier (peeks unverified `iss` only to pick keys).
- (uncarded) handlers/: scratchpad (in-memory per (identity,agent)), files (empty allowlist default; `LIMINAL_FILES_ALLOWED_PATHS`, os.pathsep-separated absolute paths, is a GRANT for a caller with no `files.allowed_paths` claim and a CEILING for one that has the claim; protected paths refused without `files:protected_writes`), web (host allowlist + private-range SSRF deny), memory (techne), notify (webhook transport).

DEPS:
- cabal → liminal: cabal/src/cabal/core/tools/mcp_proxy.py lazily imports `liminal.client.AsyncMCPClient`; cabal's pyproject registers `patterns`/`documents`/`code`/`archivist` into the `liminal.handlers` group; cabal serves `GET /admin/secrets/{persona}/{handler}` and mints the JWTs liminal verifies (single-cabal defaults `--issuer cabal-core`, `--audience liminal`).
- liminal → techne: handlers/memory.py only (lazy `import techne`; module-scope `from techne import VALID_TYPES` is inside try/except with a hardcoded fallback). CI integration job checks out tenishai/techne at the tag the Dockerfile's TECHNE_VERSION pins.
- liminal does NOT call ladon; nothing in src references it.
HEALTH: 40 test modules (tests/test_*.py), 615 tests pass (`pytest -q`, ~10-30s; memory tests importorskip techne). CI .github/workflows/test.yml: `unit` (self-hosted runner, py3.12/3.13, ruff + pytest, push/same-repo PR/dispatch), `fork-pr` (hosted twin for fork PRs), `integration` (workflow_dispatch only, with techne), `dco` (every PR into `main`: each non-merge commit needs a `Signed-off-by:` matching its author). mypy strict is configured but NOT run in CI. No branch protection: CI reports, never blocks.
GOTCHAS:
- Tool names are `<target>.<tool>`; `name.split(".",1)[0]` IS the authz key (allowlist, scope map, credential lookup). Target names must not contain `.` and must not collide with handler names (build_http_targets raises).
- Security defaults are the product: empty files allowlist, SSRF deny list, fail-closed malformed allowlist (→ deny all). Never widen one to make a test pass.
- Untrusted-result authority is `_meta["liminal/untrusted"]` + nonce, NOT the `[BEGIN UNTRUSTED TOOL RESULT]` banner text.
- `admin:*` does NOT grant `files:protected_writes` (handlers/files.py, `PROTECTED_WRITE_SCOPE in ctx.granted_scopes`, explicit membership). Outside sovereign mode `ctx.granted_scopes` is empty, so writes to protected paths are always refused: instruction files (CLAUDE.md, AGENTS.md, .cursorrules, ...), `.mcp.json`, `.claude.json`, anything under `.claude/`, `.cursor/` or `.git`, and `.github/copilot-instructions.md` (#108, #110).
- `pythonpath = ["src"]` in pyproject makes pytest test THIS tree, not the editable install (#85, fix on main via #88). Outside pytest the editable install still wins; use `PYTHONPATH=$PWD/src`.
- The stdio target transport is config-validated but NOT served (build_http_targets rejects non-http: "only 'http' is supported in Stage A", target/http.py).
- STATUS.md is a 2026-06-11 snapshot that labels itself "HISTORICAL SNAPSHOT ... not maintained"; docs/design.md labels itself "ORIGINAL PROPOSAL — the implementation diverged". Trust code over both.
RELATED DOCS: AGENTS.md (agent rules), README.md, CHANGELOG.md, CONTRIBUTING.md (incl. DCO), docs/writing-a-handler.md, docs/design.md (historical), docs/proposals/*.md (design proposals; status per file, not verified here).
