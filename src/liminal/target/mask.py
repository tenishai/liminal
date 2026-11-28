"""Mask the credentials liminal sent upstream out of what comes back (#261).

liminal knows the exact values it puts on an upstream call: the persona's
per-call token or headers, the target's static bearer, the catalog headers
and the catalog token. An upstream that echoes request headers, or a debug
error page, can hand any of them back, and the result goes to the agent. So
the HTTP target replaces each value, and its common encoded forms, in the
result content and in the upstream's error text before either leaves.

Encoded forms covered: base64 (standard and URL-safe, with and without
padding), URL-encoding (`quote` and `quote_plus`), and JSON string escaping.
A `user:secret` Basic credential is masked whole and by its secret half.
A value's base64 form is found only where it was encoded on its own; the same
bytes inside a larger base64 blob are not aligned and are not found.

Values shorter than MIN_MASK_LENGTH are skipped: replacing a 4-character
string everywhere would mangle ordinary text, and a credential that short is
not one a mask can protect anyway.

Shape borrowed from never-secret (github.com/bileet/never-secret,
`core/values.py` `with_encodings` and `mask_values`).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, quote_plus

MASK = "[redacted]"
MIN_MASK_LENGTH = 8


def with_encodings(values: Iterable[str]) -> list[str]:
    """Every value at least MIN_MASK_LENGTH long, plus its encoded forms,
    longest first so a longer form is replaced before a value inside it."""
    out: set[str] = set()
    for value in values:
        if not value:
            continue
        candidates = {value}
        user, sep, secret = value.partition(":")
        if sep and user and secret:
            candidates.add(secret)
        for raw in candidates:
            if len(raw) < MIN_MASK_LENGTH:
                continue
            out.add(raw)
            data = raw.encode()
            for enc in (base64.b64encode(data), base64.urlsafe_b64encode(data)):
                text = enc.decode()
                out.add(text)
                out.add(text.rstrip("="))
            out.add(quote(raw, safe=""))
            out.add(quote_plus(raw))
            out.add(json.dumps(raw)[1:-1])
            out.add(json.dumps(raw, ensure_ascii=False)[1:-1])
    return sorted((v for v in out if len(v) >= MIN_MASK_LENGTH), key=len, reverse=True)


def mask_text(text: str, secrets: list[str]) -> tuple[str, int]:
    """`text` with every form in `secrets` (from `with_encodings`) replaced,
    and how many replacements were made."""
    hits = 0
    for form in secrets:
        if form in text:
            hits += text.count(form)
            text = text.replace(form, MASK)
    return text, hits


def mask_content(value: Any, secrets: list[str]) -> tuple[Any, int]:
    """`value` (MCP result content: lists, dicts and strings) with every string
    in it masked, dict keys included, and the total replacements. Non-string
    leaves pass through unchanged."""
    if not secrets:
        return value, 0
    if isinstance(value, str):
        return mask_text(value, secrets)
    if isinstance(value, list):
        total = 0
        items = []
        for item in value:
            masked, n = mask_content(item, secrets)
            items.append(masked)
            total += n
        return items, total
    if isinstance(value, dict):
        total = 0
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str):
                key, n = mask_text(key, secrets)
                total += n
            masked, n = mask_content(item, secrets)
            out[key] = masked
            total += n
        return out, total
    return value, 0
