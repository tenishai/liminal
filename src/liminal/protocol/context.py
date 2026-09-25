"""The Context object carried into every handler dispatch.

Identity, agent name, and the resolved credential set live here. The
handler reads from `ctx.credentials` — liminal injects whatever Cabal Core
returns for `(identity, handler)` without filtering. The capability
card's `credential_keys` field is documentation only (per design.md).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# Records one allow/deny decision a handler made, to the server's audit log.
# Called as ``await audit(allowed=..., detail={...})``.
AuditHook = Callable[..., Awaitable[None]]


@dataclass(slots=True)
class Context:
    """Per-dispatch context handed to a handler.

    `extra` is free-form metadata liminal may forward — trace_id, span_id,
    operator-set debug flags, etc. Handlers may read it but should not
    require it.
    """

    identity: str           # persona name (e.g., "rook", "archivist")
    agent_name: str         # specific agent (e.g., "rook-primus")
    credentials: dict[str, str]
    issuer: str = ""        # verified token issuer (federated identity source)
    extra: dict[str, Any] = field(default_factory=dict)
    # Scopes from the SERVER-SIDE policy grant (sovereign mode). Never filled
    # from the caller's token, so a handler can gate on it without trusting the
    # caller; empty in single-cabal, auth-off and library mode (#108).
    granted_scopes: frozenset[str] = frozenset()
    # Set in sovereign mode, where a policy store backs the grant; None
    # otherwise. Lets a handler record its own authorization decisions through
    # ``policy_store.record_access``. Where it is None, log the decision.
    audit: AuditHook | None = None
