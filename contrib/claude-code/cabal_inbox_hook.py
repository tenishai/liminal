#!/usr/bin/env python3
"""Claude Code hook: tell the session which cabal tasks are waiting on it (cabal#314).

Register it on SessionStart and UserPromptSubmit (docs/cabal-handler.md, "Inbox").
It calls `cabal.inbox` through liminal and prints what is waiting; Claude Code adds
a hook's stdout to the session's context for both events.

- SessionStart: prints every task waiting on you.
- UserPromptSubmit: prints only when a task appears that this session has not
  been told about, so the same list doesn't repeat every turn.

It never blocks the session: any failure (liminal down, bad token, timeout)
prints nothing and exits 0; the reason goes to stderr.

Config, from the environment or ~/.config/liminal/cabal-inbox.toml (keys in
lower case without the prefix: url, token_file, timeout):
    CABAL_INBOX_URL         liminal's MCP endpoint, e.g. http://127.0.0.1:19720/mcp
    CABAL_INBOX_TOKEN_FILE  file holding the client token (the operator-local one)
    CABAL_INBOX_TIMEOUT     seconds for the call (default 5)
Stdlib only.
"""

from __future__ import annotations

import json
import os
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path.home() / ".config" / "liminal" / "cabal-inbox.toml"
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "liminal" / "cabal-inbox"
DEBUG = bool(os.environ.get("CABAL_INBOX_DEBUG"))


def _log(msg: str) -> None:
    if DEBUG:
        print(f"cabal-inbox: {msg}", file=sys.stderr)


def settings() -> dict[str, str]:
    conf: dict[str, str] = {}
    if CONFIG.is_file():
        with CONFIG.open("rb") as fh:
            conf = {k: str(v) for k, v in tomllib.load(fh).items()}
    for key in ("url", "token_file", "timeout"):
        env = os.environ.get(f"CABAL_INBOX_{key.upper()}")
        if env:
            conf[key] = env
    return conf


def fetch_inbox(url: str, token: str, timeout: float) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cabal.inbox", "arguments": {}}}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured URL
        reply = json.loads(resp.read())
    result = reply.get("result") or {}
    if result.get("isError"):
        raise RuntimeError(json.dumps(result.get("content"))[:300])
    for part in result.get("content") or []:
        if part.get("type") == "json":
            return part["data"]
        if part.get("type") == "text":
            return json.loads(part["text"])
    raise RuntimeError("cabal.inbox returned no content")


def render(waiting: list[dict], errors: list[dict], header: str) -> str:
    lines = [header]
    for e in waiting:
        where = f"group {e['group']}" if e.get("group") else e.get("agent")
        question = " ".join(str(e.get("question") or "(no question text)").split())
        if len(question) > 300:
            question = question[:297] + "..."
        lines.append(f"- task {e['task_id']} ({where}, via {e['agent']}): {question}")
    lines.append("Answer with the cabal MCP tool `cabal.answer` (agent, task_id, text); read more with `cabal.task`.")
    for err in errors:
        lines.append(f"(could not read {err.get('agent')}: {err.get('error')})")
    return "\n".join(lines)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        event = {}
    name = event.get("hook_event_name") or ""
    session = "".join(c for c in str(event.get("session_id") or "default") if c.isalnum() or c in "-_")
    conf = settings()
    if not conf.get("url") or not conf.get("token_file"):
        _log("not configured (url, token_file)")
        return 0
    try:
        token = Path(conf["token_file"]).expanduser().read_text().strip()
        inbox = fetch_inbox(conf["url"], token, float(conf.get("timeout") or 5))
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        print(f"cabal-inbox: {type(exc).__name__}: {exc}"[:300], file=sys.stderr)
        return 0
    waiting = inbox.get("waiting") or []
    errors = inbox.get("errors") or []
    ids = sorted(str(e.get("task_id")) for e in waiting)

    state = STATE_DIR / f"{session}.json"
    told: set[str] = set()
    if name != "SessionStart" and state.is_file():
        try:
            told = set(json.loads(state.read_text()))
        except ValueError:
            told = set()
    new = [e for e in waiting if str(e.get("task_id")) not in told]
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps(ids))
    except OSError as exc:
        _log(f"state not saved: {exc}")

    if name == "SessionStart":
        if waiting:
            print(render(waiting, errors, f"{len(waiting)} cabal task(s) are waiting on you:"))
    elif new:
        print(render(new, errors, f"New since you were last told: {len(new)} cabal task(s) waiting on you:"))
    _log(f"{name}: waiting={len(waiting)} new={len(new)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
