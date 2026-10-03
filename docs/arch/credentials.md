---
card: arch-card:liminal-credentials
updated: 2026-10-03
anchor: src/liminal/server/credentials.py sha=ce3879ab2e5be560845265446522abe753404eba
---
# credentials — per-(persona, handler) secrets from cabal

WHAT / SEAM: `CredentialResolver = Callable[[str, str], Awaitable[dict[str,str]]]` (identity, handler) → creds. Only implementation: `CabalCoreCredentialResolver` (server/credentials.py) → `GET {cabal_url}/admin/secrets/{persona}/{handler}` with `Authorization: Bearer <token_provider()>`; reads body `{"credentials": {...}}`, coerces to str→str.
OPS / FLOW: wired only when `liminal serve --cabal-url` is set (cli.py); token from env `--cabal-token-env` (default `LIMINAL_CABAL_TOKEN`), re-read on EVERY fetch so rotation needs no restart. cabal mints it via `cbl token mint-service --scope secrets-fetch`. routes.py:_handle_tools_call calls `resolver(claims.identity, handler_name)` after authz + secret guard; result → `ctx.credentials`. `handler_name` is the tool prefix, so federated targets resolve under their target name too (HttpTarget `service-token` reads `ctx.credentials[credential_key]`).
INVARIANTS:
- Cache per (issuer, persona, handler) (#143; the issuer is "" outside sovereign mode, and the Cabal URL stays persona/handler), TTL `--cred-cache-ttl` (default 900s). Rotation reaches liminal within TTL unless `invalidate()`/`invalidate_all()` is called — and NOTHING in src calls them (tests only). So credential revocation is TTL-gated today; authority revocation (policy.md) is live. Different axes.
- Fetch is FAIL-SOFT: network error (httpx.HTTPError), non-200, non-JSON, a JSON body that is not an object (e.g. an array), or a non-empty `credentials` value that is not an object → log + `{}` (a falsy one such as `[]`, `0` or `""` becomes `{}` silently, and is then the uncached empty answer below), never raise. These `{}` returns happen BEFORE the cache write, so a failure is never cached and the next call re-fetches. WHY: an unreachable cabal must not black-hole every tool call. The handler must treat empty creds as a refusal (HttpTarget refuses a missing/whitespace service token, #80).
- An EMPTY SUCCESSFUL answer is NOT cached: a 200 whose `credentials` is `{}`, null, `[]` or missing returns `{}` without a cache write (#140), so the next call asks cabal again and a secret added later is seen on the next call. Only a non-empty credentials dict is cached, for the TTL.
- A resolver that RAISES (custom one) → JSON-RPC ERROR_INTERNAL "credential resolution failed" (routes.py), the call does not proceed.
- No resolver wired → `ctx.credentials = {}`.
- Sovereign mode (#143): the route calls the resolver only when the caller's issuer is in the policy store's `parents()`, passing `issuer=`; a caller from any other issuer gets `ctx.credentials = {}` and liminal logs `credential.skipped_non_parent_issuer`. A persona name is unique only within its issuer, so a foreign cabal's `rook` must not receive the home `rook`'s secrets. A custom resolver wired in sovereign mode must accept the `issuer` keyword.
- Card `credential_keys` is documentation; liminal injects whatever cabal returns, unfiltered.
- Keyed by persona (`cabal_persona`), not agent (`sub`).
CONSUMERS: routes.py (HTTP path); client/library.py:_default_ctx (library mode takes the same callable); target/http.py `_build_call_headers` (reads ctx.credentials). Counterparty: cabal/src/cabal/core/routes/admin.py (serves /admin/secrets, mint-service). Tests: tests/test_credential_resolver.py.
NOT BUILT: a ladon/OpenBao-backed resolver; no code references ladon. Any new backend must keep this callable signature and the fail-soft contract.
