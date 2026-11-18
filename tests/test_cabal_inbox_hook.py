"""contrib/claude-code/cabal_inbox_hook.py: what a Claude Code session is told (cabal#314)."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / "contrib" / "claude-code" / "cabal_inbox_hook.py"


@pytest.fixture
def hook(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("cabal_inbox_hook", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    token = tmp_path / "client.jwt"
    token.write_text("tok\n")
    monkeypatch.setattr(mod, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(mod, "CONFIG", tmp_path / "absent.toml")
    monkeypatch.setenv("CABAL_INBOX_URL", "http://liminal.test/mcp")
    monkeypatch.setenv("CABAL_INBOX_TOKEN_FILE", str(token))
    return mod


def _run(mod, monkeypatch, capsys, event: str, session: str = "s-1") -> str:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": event, "session_id": session})))
    assert mod.main() == 0
    return capsys.readouterr().out


def _waiting(*ids: str) -> dict:
    return {"waiting": [{"task_id": i, "agent": "wright-secundus", "group": "wright", "question": f"q {i}?"} for i in ids]}


def test_session_start_lists_everything_waiting(hook, monkeypatch, capsys) -> None:
    seen = {}

    def fetch(url, token, timeout):
        seen.update(url=url, token=token)
        return _waiting("t-1", "t-2")

    monkeypatch.setattr(hook, "fetch_inbox", fetch)
    out = _run(hook, monkeypatch, capsys, "SessionStart")
    assert out.startswith("2 cabal task(s) are waiting on you:")
    assert "- task t-1 (group wright, via wright-secundus): q t-1?" in out
    assert "cabal.answer" in out
    assert seen == {"url": "http://liminal.test/mcp", "token": "tok"}


def test_a_prompt_mentions_only_tasks_not_yet_told(hook, monkeypatch, capsys) -> None:
    monkeypatch.setattr(hook, "fetch_inbox", lambda *a: _waiting("t-1"))
    _run(hook, monkeypatch, capsys, "SessionStart")
    assert _run(hook, monkeypatch, capsys, "UserPromptSubmit") == ""  # nothing new
    monkeypatch.setattr(hook, "fetch_inbox", lambda *a: _waiting("t-1", "t-3"))
    out = _run(hook, monkeypatch, capsys, "UserPromptSubmit")
    assert out.startswith("New since you were last told: 1 cabal task(s)")
    assert "t-3" in out and "t-1" not in out
    # Another session has been told nothing yet.
    assert "t-1" in _run(hook, monkeypatch, capsys, "UserPromptSubmit", session="s-2")


def test_nothing_waiting_prints_nothing(hook, monkeypatch, capsys) -> None:
    monkeypatch.setattr(hook, "fetch_inbox", lambda *a: {"waiting": []})
    assert _run(hook, monkeypatch, capsys, "SessionStart") == ""


def test_a_failure_never_blocks_the_session(hook, monkeypatch, capsys) -> None:
    def boom(*a):
        raise OSError("connection refused")

    monkeypatch.setattr(hook, "fetch_inbox", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "SessionStart", "session_id": "s"})))
    assert hook.main() == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "connection refused" in captured.err


def test_unconfigured_makes_no_call(hook, monkeypatch, capsys) -> None:
    monkeypatch.delenv("CABAL_INBOX_URL")
    monkeypatch.setattr(hook, "fetch_inbox", lambda *a: pytest.fail("called"))
    assert _run(hook, monkeypatch, capsys, "SessionStart") == ""


def test_fetch_reads_the_handlers_text_content(hook, monkeypatch) -> None:
    payload = {"result": {"content": [{"type": "text", "text": json.dumps(_waiting("t-9"))}], "isError": False}}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    sent = {}

    def urlopen(req, timeout):
        sent.update(auth=req.get_header("Authorization"), body=json.loads(req.data))
        return Resp(json.dumps(payload).encode())

    monkeypatch.setattr(hook.urllib.request, "urlopen", urlopen)
    assert hook.fetch_inbox("http://x/mcp", "tok", 5)["waiting"][0]["task_id"] == "t-9"
    assert sent["auth"] == "Bearer tok"
    assert sent["body"]["params"] == {"name": "cabal.inbox", "arguments": {}}
