---
card: arch-card:liminal-policy
updated: 2026-10-03
anchor: src/liminal/server/policy.py sha=802dcf8d5d7f301893dfab04237a114a514d1e90
anchor: src/liminal/server/routes.py sha=221458c82d66576e9fd29841fe1739cf32e43c19
anchor: src/liminal/server/admin.py sha=0b8d447b961ac79298d4a597699cfd5a156d9182
anchor: src/liminal/server/app.py sha=806511d7180a5b74716cc405ad318b0304fc0937
---
# policy — sovereign (multi-issuer) authorization

WHAT / SEAM: `PolicyStore` Protocol + `SqlitePolicyStore` (server/policy.py). Keyed on VERIFIED (issuer, persona). Grant = `ScopeGrant(scopes: frozenset, allowed_handlers: frozenset|None)`; `has_scope(r)` = `admin:*` in scopes or r in scopes. FLAT scopes: no delegation, caveats, attenuation, or role union.
WHY IT EXISTS: a sovereign liminal trusts several independently-owned cabals; any of them could mint itself generous `scope`/`tool_extras`. So in sovereign mode authz comes from this store, never from the token.
OPS / FLOW (routes.py):
- `_authenticate`: no store → single-cabal path (`_token_scopes`: token `cabal_scope`, falling back to `scope`, must contain `dispatch`; grant=None). Store → `resolve(iss, persona)`; None → record `access_deny` + AuthError.
- `_allowed_handlers_for`: grant present → grant.allowed_handlers (None=all, empty=deny all); else token `cabal_tool_extras|tool_extras["liminal.allowed_handlers"]`; malformed → empty set (deny).
- `_missing_scope` via `app.state.policy_scope_for` (app.py:scope_for): exact `<t>.<tool>` rule → target rule → `DENY_SCOPE` ("liminal:deny", server/scopes.py) if target declares tool_scopes → None (open). Only runs when a grant exists.
- `_operator_refusal` (cabal#233) runs in EVERY mode, after the scope gate: a tool whose card sets `requires_operator` (app.state.operator_only) needs `operator` in the GRANT when one exists (`admin:*` satisfies it), else in the verified token's scope in single-cabal mode; auth-disabled refuses outright. Denials under a grant are recorded as `access_deny` with `required_scope`=operator.
- tools/list filters with the SAME three functions as tools/call (allowlist, `_missing_scope`, `_operator_refusal`; #61), so discovery cannot drift from enforcement.
- Sovereign: `ctx.extra` = operator `[tool_extras]` from the trust registry (policy_tool_extras), token extras ignored; `ctx.granted_scopes` = grant.scopes; `ctx.audit` = partial(record_access).
RESOLUTION: data plane `resolve` = exact persona → (issuer,"*") → None, parent rows EXCLUDED on both legs (#73). Admin plane `resolve_parent` = parent rows only. FAIL-CLOSED.
INVARIANTS:
- Parent rows (`is_parent=1`, admin:*) are seeded at boot per `admin_personas`, immutable: grant/revoke raise ParentImmutable. WHY: "graduation does not orphan".
- Opening a store whose `is_parent` rows name an issuer other than the configured parent (or any parent row when no parent issuer is configured) raises ParentIssuerDemoted, a ParentNarrowingConflict subclass, before anything is seeded (#87, #134); the CLI's ParentNarrowingConflict handler exits 2, and a new policy DB is required. WHY: the persona check compares within one issuer, so a demoted issuer's rows would otherwise keep answering `parents()` and the admin gate.
- Dropping ANY previously seeded parent persona raises ParentNarrowingConflict (cli exit 2); new policy DB required. WHY: seeding is idempotent and rows immutable, so a narrowing would be a silent no-op leaving the dropped persona admin (#83). `"*"` in wanted = widening, allowed.
- cli refuses a parent issuer with no `admin_personas`; `["*"]` is allowed with a warning.
- MultiIssuerJWKSVerifier without a policy_store → ConfigError (app.py). Store + auth-disabled → warning, store inert.
- Never tell an operator to grant `liminal:deny`: it is a sentinel and granting it disables deny-by-default. Refusal text avoids naming it as grantable.
- Federated-target scopes come from operator TargetSpec config, never the fetched catalog (an untrusted upstream would declare it needs none). `[scope_map]` in the trust registry is deprecated and ignored.
- Audit = `policy_audit` ring buffer (audit_max_rows=50k, pruned every 500 writes) to stop a hostile partner filling the DB. NOT tamper-evident, no hash chain. Actions: access_allow/access_deny/grant/revoke; the three tool-level deny paths in routes.py (handler allowlist, scope gate, operator gate) record a `handler` key in the deny row (#44); the no-grant deny in `_authenticate` records only `{"reason": "no grant"}`.
- Authority revocation is LIVE per call (revoke deletes the row; resolve reads the DB each request). Credential staleness is a separate axis: docs/arch/credentials.md.
- All SQLite access serialized by an asyncio.Lock + to_thread on one connection.
CONSUMERS: server/routes.py (data plane), server/admin.py (`_admin_auth`: issuer in store.parents() AND resolve_parent has admin:*), handlers/files.py (`files:protected_writes` via ctx.granted_scopes + ctx.audit), cli.py (builds store from `--trust-registry`/`--policy-db`). Tests: test_policy_store.py, test_policy_inversion.py, test_multi_issuer_auth.py, test_federated_tool_scopes.py.
API: admin routes (admin.py, parent-issuer token with admin:*): POST /admin/policy/grant {issuer, persona="*", scopes, allowed_handlers}, POST /admin/policy/revoke {issuer, persona}, GET /admin/policy, GET /admin/policy/audit. Mounted on the data app unless `--admin-port` moves it to create_admin_app (#74).
