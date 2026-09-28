---
card: arch-card:liminal-policy
updated: 2026-09-28
anchor: src/liminal/server/policy.py sha=8d1c6df0b4e18aaefd638a39e836e54f640e00b8
anchor: src/liminal/server/routes.py sha=075e824a79c6e73ade1da5c44e04cce08a03c994
anchor: src/liminal/server/admin.py sha=0b8d447b961ac79298d4a597699cfd5a156d9182
anchor: src/liminal/server/app.py sha=3ba114c0c089c040b2be1e26b0867e8b8a35e55c
---
# policy — sovereign (multi-issuer) authorization

WHAT / SEAM: `PolicyStore` Protocol + `SqlitePolicyStore` (server/policy.py). Keyed on VERIFIED (issuer, persona). Grant = `ScopeGrant(scopes: frozenset, allowed_handlers: frozenset|None)`; `has_scope(r)` = `admin:*` in scopes or r in scopes. FLAT scopes: no delegation, caveats, attenuation, or role union.
WHY IT EXISTS: a sovereign liminal trusts several independently-owned cabals; any of them could mint itself generous `scope`/`tool_extras`. So in sovereign mode authz comes from this store, never from the token.
OPS / FLOW (routes.py):
- `_authenticate` (:60): no store → single-cabal path (token scope must contain `dispatch`, grant=None). Store → `resolve(iss, persona)`; None → record `access_deny` + AuthError.
- `_allowed_handlers_for` (:282): grant present → grant.allowed_handlers (None=all, empty=deny all); else token `cabal_tool_extras|tool_extras["liminal.allowed_handlers"]`; malformed → empty set (deny).
- `_missing_scope` (:263) via `app.state.policy_scope_for` (app.py:scope_for): exact `<t>.<tool>` rule → target rule → `DENY_SCOPE` ("liminal:deny", server/scopes.py) if target declares tool_scopes → None (open). Only runs when a grant exists.
- tools/list filters with the SAME two functions as tools/call (#61), so discovery cannot drift from enforcement.
- Sovereign: `ctx.extra` = operator `[tool_extras]` from the trust registry (policy_tool_extras), token extras ignored; `ctx.granted_scopes` = grant.scopes; `ctx.audit` = partial(record_access).
RESOLUTION: data plane `resolve` = exact persona → (issuer,"*") → None, parent rows EXCLUDED on both legs (#73). Admin plane `resolve_parent` = parent rows only. FAIL-CLOSED.
INVARIANTS:
- Parent rows (`is_parent=1`, admin:*) are seeded at boot per `admin_personas`, immutable: grant/revoke raise ParentImmutable. WHY: "graduation does not orphan".
- Dropping ANY previously seeded parent persona raises ParentNarrowingConflict (cli exit 2); new policy DB required. WHY: seeding is idempotent and rows immutable, so a narrowing would be a silent no-op leaving the dropped persona admin (#83). `"*"` in wanted = widening, allowed.
- cli refuses a parent issuer with no `admin_personas`; `["*"]` is allowed with a warning.
- MultiIssuerJWKSVerifier without a policy_store → ConfigError (app.py). Store + auth-disabled → warning, store inert.
- Never tell an operator to grant `liminal:deny`: it is a sentinel and granting it disables deny-by-default. Refusal text avoids naming it as grantable.
- Federated-target scopes come from operator TargetSpec config, never the fetched catalog (an untrusted upstream would declare it needs none). `[scope_map]` in the trust registry is deprecated and ignored.
- Audit = `policy_audit` ring buffer (audit_max_rows=50k, pruned every 500 writes) to stop a hostile partner filling the DB. NOT tamper-evident, no hash chain. Actions: access_allow/access_deny/grant/revoke; deny rows carry `handler` key on both deny paths (#44).
- Authority revocation is LIVE per call (revoke deletes the row; resolve reads the DB each request). Credential staleness is a separate axis: docs/arch/credentials.md.
- All SQLite access serialized by an asyncio.Lock + to_thread on one connection.
CONSUMERS: server/routes.py (data plane), server/admin.py (`_admin_auth`: issuer in store.parents() AND resolve_parent has admin:*), handlers/files.py (`files:protected_writes` via ctx.granted_scopes + ctx.audit), cli.py (builds store from `--trust-registry`/`--policy-db`). Tests: test_policy_store.py, test_policy_inversion.py, test_multi_issuer_auth.py, test_federated_tool_scopes.py.
API: admin routes (admin.py, parent-issuer token with admin:*): POST /admin/policy/grant {issuer, persona="*", scopes, allowed_handlers}, POST /admin/policy/revoke {issuer, persona}, GET /admin/policy, GET /admin/policy/audit. Mounted on the data app unless `--admin-port` moves it to create_admin_app (#74).
