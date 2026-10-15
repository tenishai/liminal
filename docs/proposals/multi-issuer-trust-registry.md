# Multi-Issuer Trust Registry — spec

|  |  |
| --- | --- |
| **Status** | Implemented (`MultiIssuerJWKSVerifier` and `_aud_ok` in `src/liminal/server/auth.py`) |
| **Authors** | Richard DiMartino + AI |
| **Created** | 2026-07-02 |
| **Implements** | `cabal/docs/proposals/federated-singletons.md` "What's new #1" |
| **Touches** | `src/liminal/server/auth.py`, `src/liminal/server/routes.py`, `src/liminal/cli.py` |

---

## Purpose

Let a **sovereign** liminal deployment (a graduated singleton persona — e.g. a
federated Archivist) accept callers from **multiple cabals**, each its own IdP,
while keeping authorization owned by the sovereign service rather than by any
caller's cabal.

Before implementation, liminal trusted exactly one issuer (`URLJWKSVerifier` with a single
`jwks_url`/`expected_issuer`) and derived authorization from claims
the token itself carries — `scope` and
`tool_extras.liminal.allowed_handlers`. That is correct only
because, in the single-cabal case, **the token's issuer is also the policy
authority**. Federation breaks that assumption: shaz's Cabal Core would happily
mint shaz's agents any scope they ask for. So this spec has two halves:

1. **Authentication** — a `MultiIssuerJWKSVerifier` that selects the right JWKS by
   the token's `iss` and verifies against it (reusing `URLJWKSVerifier` per issuer).
2. **Authorization inversion** — a server-side `PolicyStore` keyed on the *verified*
   `(issuer, persona)`, which **replaces** token-embedded scope/allowlist for
   sovereign deployments. The parent is simply the issuer whose policy row is a
   permanent `admin:*`.

Single-cabal deployments are unchanged: no registry, no `PolicyStore` → today's
token-embedded path stays exactly as-is.

---

## Part 1 — Authentication: `MultiIssuerJWKSVerifier`

### 1.1 `VerifiedClaims` gains `issuer`

Authorization must key on *which cabal* the caller belongs to, so the verified
issuer has to survive into the claims. Additive, backward-compatible:

```python
@dataclass(slots=True)
class VerifiedClaims:
    identity: str
    agent_name: str
    raw: dict[str, Any]
    issuer: str = ""          # NEW: the verified `iss`. "" for legacy/anonymous.
```

The two synthetic constructions in `routes.py` (auth-disabled anonymous, ~line 126)
keep working via the default; set `issuer="local"` there for clarity.

### 1.2 `_verify_against_keyset` — parametrize issuer + fix `aud` list handling

Two changes to the shared helper (`auth.py:167`):

**(a) Record the verified issuer.** It already checks
`claims.get("iss") != expected_issuer` (`auth.py:187`); now also stamp it onto the
result so callers can route on it:

```python
return VerifiedClaims(
    identity=str(persona), agent_name=str(sub), raw=claims,
    issuer=str(claims.get("iss")),      # NEW
)
```

**(b) Accept list-valued `aud`.** This is a real bug for federation, not cosmetic.
The current check is exact string equality (`auth.py:190`):

```python
if expected_audience is not None and claims.get("aud") != expected_audience:
    raise AuthError("invalid_audience")
```

Cabal mints **per-target** tokens (cabal `D-010`), and RFC 7519 `aud` is commonly a
list. A dispatch to the sovereign service will carry `aud` = `[..., "archivist@rd"]`.
Replace with membership-aware matching:

```python
def _aud_ok(aud: Any, expected: str | None) -> bool:
    if expected is None:
        return True
    if isinstance(aud, str):
        return aud == expected
    if isinstance(aud, (list, tuple)):
        return expected in aud
    return False

# in _verify_against_keyset:
if not _aud_ok(claims.get("aud"), expected_audience):
    raise AuthError("invalid_audience")
```

This benefits the single-cabal path too (it was list-broken before `_aud_ok`).

### 1.3 The verifier — compose, don't rewrite

Wrap one `URLJWKSVerifier` **per issuer** so each issuer keeps its own TTL cache and
kid-miss re-fetch (`auth.py:127`, `auth.py:149`) for free, and one issuer's JWKS
outage only affects that issuer's callers:

```python
def _peek_iss(token: str) -> str | None:
    """Read the UNVERIFIED `iss` to select which JWKS to verify against.
    Selection only — never trusted. If an attacker lies about `iss` to pick
    issuer X's keys, the signature won't verify against X and the token is
    rejected in _verify_against_keyset. Safe by construction.
    """
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg)).get("iss")
    except Exception:
        return None


@dataclass
class MultiIssuerJWKSVerifier:
    # issuer id -> the single-issuer verifier for that cabal
    registry: dict[str, URLJWKSVerifier]
    parents: frozenset[str] = frozenset()   # issuers with guardian standing

    async def verify(self, token: str) -> VerifiedClaims:
        iss = _peek_iss(token)
        if iss is None:
            raise AuthError("token missing iss claim")
        inner = self.registry.get(iss)
        if inner is None:
            raise AuthError(f"untrusted issuer: {iss!r}")
        # Delegates the real work: signature vs that issuer's JWKS, RS256 pin,
        # iss/aud/exp/iat, persona+sub. Returns VerifiedClaims with .issuer set.
        return await inner.verify(token)
```

It satisfies the existing `JWTVerifier` Protocol (`auth.py:56`) verbatim, so it drops
into `request.app.state.jwt_verifier` with no route changes for *authentication*.

Each inner `URLJWKSVerifier` is constructed with `expected_issuer=<that issuer id>`
and `expected_audience=<this service's own id>`, so the delegated verify re-confirms
`iss` (defense-in-depth over the peeked value) and enforces the audience gate.

### 1.4 Construction from the trust registry

The `[[issuer]]` config from the federated-singletons doc maps directly:

```python
@dataclass(frozen=True, slots=True)
class IssuerConfig:
    id: str
    jwks_uri: str
    parent: bool = False

def build_multi_issuer_verifier(
    issuers: list[IssuerConfig], *, service_audience: str,
) -> MultiIssuerJWKSVerifier:
    registry = {
        i.id: URLJWKSVerifier(
            jwks_url=i.jwks_uri,
            expected_issuer=i.id,
            expected_audience=service_audience,   # this sovereign service's id
        )
        for i in issuers
    }
    parents = frozenset(i.id for i in issuers if i.parent)
    if len(parents) != 1:
        raise ValueError("exactly one parent issuer required")
    return MultiIssuerJWKSVerifier(registry=registry, parents=parents)
```

`service_audience` is the graduated persona's stable service id (e.g. `archivist@rd`),
which is what callers must mint into `aud`. This enforces §3 of the design doc.

CLI wiring (`cli.py:92`) grows a `--trust-registry <path.toml>` branch alongside the
existing `--jwks-url` single-issuer branch:

```
--jwks-url URL --issuer ID        → URLJWKSVerifier          (single cabal, today)
--trust-registry registry.toml    → MultiIssuerJWKSVerifier  (sovereign)
```

Exactly one may be set. Absent both → the existing "reject every request" warning.

---

## Part 2 — Authorization inversion: server-side `PolicyStore`

Authentication proves *who* the caller is `(issuer, persona, agent)`. In sovereign
mode the sovereign service — not the caller's cabal — decides *what they may do*.

### 2.1 The store

```python
@dataclass(frozen=True, slots=True)
class ScopeGrant:
    scopes: frozenset[str]                       # {"mem:query","mem:append",...,"admin:*"}
    allowed_handlers: frozenset[str] | None = None   # None = all handlers this service exposes

class PolicyStore(Protocol):
    def resolve(self, issuer: str, persona: str) -> ScopeGrant | None: ...
```

Backed by the sovereign service's own table (SQLite alongside its techne store),
managed by the parent via the `cbl federation grant/revoke/ls` surface. Seeded at
graduation with one immutable row: `(parent_issuer, "*") → {"admin:*", ...all}`.
Resolution precedence: exact `(issuer, persona)` → `(issuer, "*")` → deny.

### 2.2 Where it plugs into `routes.py`

**`_authenticate` (routes.py:55).** After `verifier.verify`, branch on whether a
`PolicyStore` is configured:

- **No `PolicyStore`** (single-cabal, today): keep the token-embedded check —
  `scope`/`cabal_scope` must contain `"dispatch"` (routes.py:70-72). Unchanged.
- **`PolicyStore` present** (sovereign): **ignore** token-embedded `scope`. Resolve
  `grant = store.resolve(claims.issuer, claims.identity)`; deny if `None`. Require
  the method's needed scope to be in `grant.scopes` (e.g. `tools/call` on a
  `mem:append` handler needs `mem:append`; `admin/*` methods need `admin:*`). Stash
  the grant on the request for the allowlist step.

**`_allowed_handlers_for` (routes.py:210).** Add a sovereign branch: when a grant is
present, the allowlist is `grant.allowed_handlers` (server-authoritative), **not**
`claims.raw["tool_extras"]`. The token-embedded path remains for single-cabal.

This is the crux: `tool_extras`/`allowed_handlers` in a *foreign* token is advisory
at best and hostile at worst — in sovereign mode it is never trusted.

### 2.3 Parent dual-plane

The parent authenticates like any caller (its home JWT, verified via its registry
entry). Its `admin:*` grant is a **PolicyStore row**, not a token claim — so the
data plane and the admin plane share one auth path but diverge purely on
server-side policy. `parents` on the verifier is a cheap guard (reject an `admin/*`
method whose `claims.issuer not in verifier.parents` before even hitting the store).

---

## Backward compatibility

| Deployment | Verifier | Authorization | Change |
|---|---|---|---|
| Single cabal (today) | `URLJWKSVerifier` | token-embedded `scope` + `tool_extras` | `aud` now list-aware; `VerifiedClaims.issuer` populated. Otherwise none. |
| Sovereign | `MultiIssuerJWKSVerifier` | server-side `PolicyStore` on `(issuer, persona)` | new code, opt-in via `--trust-registry` + a store |

Nothing in Part 2 activates unless a `PolicyStore` is wired. The `aud` fix (1.2b)
and the `issuer` field (1.1) are the only changes touching the existing path, both
safe.

---

## Security notes

- **Unverified `iss` peek is selection-only.** Trust is established solely by
  signature verification against the selected issuer's JWKS. A forged `iss` selects
  keys the token can't validate against → rejected.
- **Fail closed everywhere.** Unknown issuer → deny. Missing `PolicyStore` grant →
  deny. Malformed policy → deny (mirrors `_allowed_handlers_for`'s existing
  fail-closed posture, routes.py:225/230).
- **Revocation via TTL.** Inter-agent tokens are short (cabal: access 5m). Revoking
  an issuer or narrowing a grant takes effect within a token lifetime; no CRL. JWKS
  key rotation propagates within the 300s cache TTL or immediately on kid-miss
  (`auth.py:149`).
- **Blast-radius isolation.** Per-issuer `URLJWKSVerifier` means one cabal's JWKS
  endpoint being down denies only that cabal's callers.
- **Algorithm pin** (RS256, `auth.py:182`) is inherited unchanged — keep it; it's the
  algorithm-confusion defense and every federated cabal already signs RS256.

---

## Test plan

Extend the existing `tests/` auth suite:

1. **Routing** — token from issuer A verifies against A's JWKS; token whose `iss`
   isn't in the registry → `untrusted issuer`.
2. **Cross-key rejection** — token signed by B but claiming `iss=A` → signature fails
   against A's keys (proves the peek can't be exploited).
3. **`aud` list** — `aud=["x", service_id]` passes; `aud=["x"]` fails; bare string
   still works (regression for single-cabal).
4. **Per-issuer cache isolation** — A's JWKS 503 doesn't break B's verification.
5. **Policy inversion** — foreign token carrying `tool_extras.allowed_handlers=[all]`
   but a `PolicyStore` grant of `{mem:query}` → only query handlers visible/callable;
   append denied. Proves token-embedded authz is ignored in sovereign mode.
6. **Parent plane** — parent issuer with `admin:*` reaches `admin/*`; non-parent with
   full data scope is rejected at `admin/*` by the `parents` guard.
7. **kid-miss re-fetch** still works per-issuer (regression over `auth.py:149`).

---

## Open items

- **Method→scope mapping.** Which sovereign methods require which scope
  (`mem:append` vs `mem:query` vs `admin:*`) should derive from the persona's actual
  handler set, not be hard-coded here. Define alongside the Archivist scope
  vocabulary (federated-singletons.md open question).
- **`PolicyStore` schema + `cbl federation` admin endpoints** are their own spec
  (the admin surface in federated-singletons.md §CLI).
- **`nbf`/clock-skew** across independently-operated cabals — the existing 30s leeway
  (`DEFAULT_LEEWAY_SECONDS`) may want widening for federation; confirm against real
  clock drift before changing.
```
