"""The Context object carried into every handler dispatch.

Identity, agent name, and the resolved credential set live here. The
handler reads from `ctx.credentials` — limenal injects whatever Cabal Core
returns for `(identity, handler)` without filtering. The capability
card's `credential_keys` field is documentation only (per design.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Context:
    """Per-dispatch context handed to a handler.

    `extra` is free-form metadata limenal may forward — trace_id, span_id,
    operator-set debug flags, etc. Handlers may read it but should not
    require it.
    """

    identity: str           # persona name (e.g., "rook", "archivist")
    agent_name: str         # specific agent (e.g., "rook-primus")
    credentials: dict[str, str]
    issuer: str = ""        # verified token issuer (federated identity source)
    extra: dict[str, Any] = field(default_factory=dict)
