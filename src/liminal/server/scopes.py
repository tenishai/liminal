"""Scope constants shared by the resolver and the gate.

``DENY_SCOPE`` lives here rather than in ``app`` so ``routes`` can name it
without importing ``app`` (which imports ``routes``).
"""

from __future__ import annotations

# A scope no grant should ever hold. Returned for a tool on a deny-by-default
# target that no operator rule names (liminal#78). `admin:*` still satisfies it,
# which is deliberate and consistent with every other gate — see
# ScopeGrant.has_scope. It is a SENTINEL: granting it literally disables the
# deny-by-default gate, which is why the refusal message refuses to name it as
# something to grant.
DENY_SCOPE = "liminal:deny"

# The scope an operator-only tool requires (a tool card's ``requires_operator``).
# Matches cabal's own definition of an operator: "operator" in cabal_scope.
OPERATOR_SCOPE = "operator"
