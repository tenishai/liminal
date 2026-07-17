"""Fail-closed pre-persist secret guard (limenal#50, architect pattern 22635ec3).

Scans the content of write-path tools *before* dispatch and blocks the call if
it looks like a real secret is about to be persisted or emitted. Placeholder
forms (``REDACTED``, ``<...>``, ``${VAR}``, bare env-refs) are allowlisted so
legitimate config templates and redacted examples aren't blocked.

Design notes:
- The scan is deliberately shape-based (key/token *shapes*), not entropy-based
  — cheap, deterministic, and easy to reason about at the route boundary.
- It is FAIL-CLOSED: a non-empty result — or any exception raised while
  scanning — must be treated by the caller as "block". The route wiring never
  lets a scanner error through as a successful write.
- Lifted from blitzdotdev/blitzos `build-monorepo.sh::reject_secret_material`,
  whose key insight is the placeholder allowlist: catch key-*shaped* strings
  while letting documented placeholders through, so the guard stays usable.
"""

from __future__ import annotations

import re

# Which write-path tool maps to which string argument(s) carrying the content
# that gets persisted/emitted. Only these tools are scanned; everything else
# (reads, scratchpad, etc.) passes untouched.
GUARDED_FIELDS: dict[str, tuple[str, ...]] = {
    "files.write": ("content",),
    "memory.commit": ("content",),
    "notify.send": ("message", "title"),
}

# (name, pattern). For patterns with a capture group, group(1) is the *value*
# that gets placeholder-checked; for whole-match token shapes there is no group
# and the whole match is the value (a real token shape, never a placeholder).
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem_private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # sk- covers OpenAI (sk-, sk-proj-) and Anthropic (sk-ant-api03-…). Allow
    # internal -/_ so a hyphenated project/vendor key isn't split at the hyphen
    # (a naked `sk-ant-…` would otherwise slip past a contiguous-alnum shape).
    # The (?=…[0-9]) lookahead requires at least one digit in the tail, which
    # prunes long kebab-case slugs (e.g. a `sk-skeleton-loader-…` CSS class in a
    # files.write payload) that would otherwise trip the guard as a fail-closed
    # false positive (limenal#52). Real sk- keys always contain digits.
    ("sk_api_key", re.compile(r"\bsk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}\b")),
    # Generic `key = value` assignment of a long, unbroken token. group(1) is
    # the value, which is placeholder-checked below.
    ("assigned_secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b"
        r"\s*[:=]\s*['\"]?([^\s'\"]{12,})")),
)

# A value that is *entirely* one of these is a documented placeholder, not a
# secret: REDACTED, <ANY_ANGLE_TAG>, ${VAR}, $ENV_VAR, xxxxxx, ****, changeme,
# your-token, example-key, placeholder..., ellipsis.
_PLACEHOLDER = re.compile(
    r"^(?:REDACTED|<[^>]+>|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|x{6,}|\*{4,}|changeme|your[-_][a-z]+(?:[-_][a-z]+)*"
    r"|example[-_][a-z]+(?:[-_][a-z]+)*|placeholder[a-z_-]*|\.\.\.)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


def scan_for_secrets(text: str) -> list[str]:
    """Return the sorted names of secret patterns matched in ``text``.

    Empty list == clean. A non-empty list == the caller must block (fail-closed).
    Documented placeholders are not counted as hits.
    """
    if not text:
        return []
    hits: set[str] = set()
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(1) if m.lastindex else m.group(0)
            if _is_placeholder(value):
                continue
            hits.add(name)
    return sorted(hits)


def scan_tool_call(tool_name: str, arguments: object) -> list[str]:
    """Scan the guarded content field(s) of a write-path tool call.

    Returns the sorted matched-pattern names ([] == clean or unguarded tool).
    Non-string / missing fields are skipped; a non-dict ``arguments`` is clean.
    """
    fields = GUARDED_FIELDS.get(tool_name)
    if not fields or not isinstance(arguments, dict):
        return []
    hits: set[str] = set()
    for field in fields:
        value = arguments.get(field)
        if isinstance(value, str):
            hits.update(scan_for_secrets(value))
    return sorted(hits)
