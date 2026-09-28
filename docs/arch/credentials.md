---
card: arch-card:liminal-credentials
updated: 2026-09-28
anchor: src/liminal/server/credentials.py sha=739bb1e6c33b9a00f45360a2a28fe6908bb7f52f
---
# credentials — per-(persona, handler) secrets from cabal

WHAT / SEAM: `CredentialResolver = Callable[[str, str], Awaitable[dict[str,str]]]` (identity, handler) → creds. Only implementation: `CabalCoreCredentialResolver` (server/credentials.py) → `GET {cabal_url}/admin/secrets/{persona}/{handler}` with `Authorization: Bearer <token_provider()>`; reads body `{"credentials": {...}}`, coerces to str→str.
OPS / FLOW: wired only when `liminal serve --cabal-url` is set (cli.py); token from env `--cabal-token-env` (default `LIMINAL_CABAL_TOKEN`), re-read on EVERY fetch so rotation needs no restart. cabal mints it via `cbl token mint-service --scope secrets-fetch`. routes.py:457 calls `resolver(claims.identity, handler_name)` after authz + secret guard; result → `ctx.credentials`. `handler_name` is the tool prefix, so federated targets resolve under their target name too (HttpTarget `service-token` reads `ctx.credentials[credential_key]`).
INVARIANTS:
- Cache per (persona, handler), TTL `--cred-cache-ttl` (default 900s). Rotation reaches liminal within TTL unless `invalidate()`/`invalidate_all()` is called — and NOTHING in src calls them (tests only). So credential revocation is TTL-gated today; authority revocation (policy.md) is live. Different axes.
- Fetch is FAIL-SOFT: network error, non-200, non-JSON, wrong shape → log + `{}`, never raise. WHY: an unreachable cabal must not black-hole every tool call. The handler must treat empty creds as a refusal (HttpTarget refuses a missing/whitespace service token, #80). Empty results are NOT cached.
- A resolver that RAISES (custom one) → JSON-RPC ERROR_INTERNAL "credential resolution failed" (routes.py), the call does not proceed.
- No resolver wired → `ctx.credentials = {}`.
- Card `credential_keys` is documentation; liminal injects whatever cabal returns, unfiltered.
- Keyed by persona (`cabal_persona`), not agent (`sub`).
CONSUMERS: routes.py (HTTP path); client/library.py:_default_ctx (library mode takes the same callable); target/http.py `_build_call_headers` (reads ctx.credentials). Counterparty: cabal/src/cabal/core/routes/admin.py (serves /admin/secrets, mint-service). Tests: tests/test_credential_resolver.py.
NOT BUILT: a ladon/OpenBao-backed resolver. The July card's "repoint resolver to ladon for federation" was a plan; no code references ladon. Any new backend must keep this callable signature and the fail-soft contract.
