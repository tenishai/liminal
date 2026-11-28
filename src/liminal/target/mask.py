"""Mask the credentials liminal sent upstream out of what comes back (#261).

liminal knows the exact values it puts on an upstream call: the persona's
per-call token or headers, the target's static bearer, the catalog headers
and the catalog token. An upstream that echoes request headers, or a debug
error page, can hand any of them back, and the result goes to the agent. So
the HTTP target replaces each value, and its common encoded forms, in the
result content and in the upstream's error text before either leaves.

Encoded forms covered: base64 (standard and URL-safe, with and without
padding), URL-encoding (`quote` and `quote_plus`, with upper- or lowercase
`%xx`), JSON string escaping (with and without `\\/` for `/`), and hex (upper-
and lowercase). A `user:secret` Basic credential is masked whole and by its
secret half.

Not covered, and so still able to leak: a value's base64 form inside a larger
base64 blob (the bytes are not aligned), a value split across content blocks
or broken up by inserted characters, mixed-case hex or percent-encoding, and
any encoding not listed above. An upstream that wants to leak a credential it
was sent can always do so; this stops the accidental echo, not a hostile one.

Values shorter than MIN_MASK_LENGTH are skipped: replacing a 4-character
string everywhere would mangle ordinary text, and a credential that short is
not one a mask can protect anyway.

Shape borrowed from never-secret (github.com/bileet/never-secret,
`core/values.py` `with_encodings` and `mask_values`).
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, quote_plus

MASK = "[redacted]"
_PCT = re.compile(r"%[0-9A-F]{2}")
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
            for q in (quote(raw, safe=""), quote_plus(raw)):
                out.add(q)
                out.add(_PCT.sub(lambda m: m.group(0).lower(), q))
            for j in (json.dumps(raw)[1:-1], json.dumps(raw, ensure_ascii=False)[1:-1]):
                out.add(j)
                out.add(j.replace("/", "\\/"))
            out.add(data.hex())
            out.add(data.hex().upper())
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
                # Two keys can mask to the same text; number the later ones
                # rather than let one silently replace the other.
                base, k = key, 2
                while key in out:
                    key, k = f"{base}#{k}", k + 1
            masked, n = mask_content(item, secrets)
            out[key] = masked
            total += n
        return out, total
    return value, 0
