"""cabal handler (liminal#189): MCP tools over cabal's A2A v1.0 endpoint."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from liminal.handlers.cabal import CabalHandler, agents_in, summarize, token_key
from liminal.protocol import Context

BASE = "http://cabal.test"
TOKEN = "tok-secundus-SECRET"


def _ctx(credentials: dict[str, str] | None = None) -> Context:
    return Context(
        identity="operator-local",
        agent_name="operator-local",
        credentials={"CABAL_TOKEN_WRIGHT_SECUNDUS": TOKEN} if credentials is None else credentials,
    )


def _handler(fn) -> tuple[CabalHandler, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return fn(request)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(record))

    return CabalHandler(base_url=BASE, http_client_factory=factory), seen


def _task(state: str = "TASK_STATE_SUBMITTED", **extra: Any) -> dict[str, Any]:
    return {
        "id": "t-1",
        "contextId": "c-1",
        "status": {
            "state": state,
            "timestamp": "2026-11-17T12:00:00Z",
            "message": {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "on it"}]},
        },
        **extra,
    }


def _ok(result: dict[str, Any]):
    def fn(request: httpx.Request) -> httpx.Response:
        rid = json.loads(request.content)["id"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})

    return fn


def _data(result) -> dict[str, Any]:
    assert not result.is_error, result.error
    return result.content[0]["data"]


# ---- names and summaries ------------------------------------------------


def test_token_key_and_agents_in_round_trip() -> None:
    assert token_key("wright-secundus") == "CABAL_TOKEN_WRIGHT_SECUNDUS"
    creds = {
        "CABAL_TOKEN_WRIGHT_SECUNDUS": "a",
        "CABAL_TOKEN_PRUDENCE": "b",
        "CABAL_TOKEN_EMPTY": "",  # no value: not a grant
        "OTHER_KEY": "c",
    }
    assert agents_in(creds) == ["prudence", "wright-secundus"]


def test_summarize_maps_state_and_collects_text() -> None:
    task = _task(
        "TASK_STATE_INPUT_REQUIRED",
        artifacts=[{"artifactId": "a", "name": "report", "parts": [{"text": "done"}, {"data": {}}]}],
        metadata={"cabal_group": "wright"},
    )
    out = summarize(task)
    assert out["state"] == "input-required"
    assert out["status_message"] == "on it"
    assert out["artifacts"] == [{"name": "report", "text": "done"}]
    assert out["group"] == "wright"


# ---- send ---------------------------------------------------------------


async def test_send_returns_immediately_with_the_task() -> None:
    handler, seen = _handler(_ok({"task": _task()}))
    result = await handler.dispatch("send", {"agent": "wright-secundus", "message": "port reflect"}, _ctx())
    data = _data(result)
    assert data["outcome"] == "sent"
    assert data["task_id"] == "t-1"
    assert data["state"] == "submitted"

    (req,) = seen
    assert str(req.url) == f"{BASE}/agents/wright-secundus/a2a"
    assert req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert req.headers["A2A-Version"] == "1.0"
    body = json.loads(req.content)
    assert body["method"] == "SendMessage"
    assert body["params"]["configuration"] == {"returnImmediately": True}
    msg = body["params"]["message"]
    assert msg["role"] == "ROLE_USER"
    assert msg["parts"] == [{"text": "port reflect"}]
    assert msg["contextId"]  # generated, so an uncertain send can be settled
    assert "metadata" not in body["params"]


async def test_send_to_a_group_sets_cabal_group() -> None:
    handler, seen = _handler(_ok({"task": _task()}))
    await handler.dispatch(
        "send", {"agent": "wright-secundus", "message": "x", "group": "wright", "context_id": "c-9"}, _ctx()
    )
    params = json.loads(seen[0].content)["params"]
    assert params["metadata"] == {"cabal_group": "wright"}
    assert params["message"]["contextId"] == "c-9"


async def test_send_that_times_out_is_uncertain_not_failed() -> None:
    def fn(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    handler, seen = _handler(fn)
    result = await handler.dispatch("send", {"agent": "wright-secundus", "message": "x"}, _ctx())
    data = _data(result)
    assert data["outcome"] == "uncertain"
    sent_context = json.loads(seen[0].content)["params"]["message"]["contextId"]
    assert data["context_id"] == sent_context
    assert "cabal.tasks" in data["next"]


async def test_send_on_a_5xx_is_uncertain() -> None:
    handler, _ = _handler(lambda r: httpx.Response(502, text="bad gateway"))
    result = await handler.dispatch("send", {"agent": "wright-secundus", "message": "x"}, _ctx())
    assert _data(result)["outcome"] == "uncertain"


async def test_send_that_cannot_connect_is_a_plain_failure() -> None:
    def fn(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    handler, _ = _handler(fn)
    result = await handler.dispatch("send", {"agent": "wright-secundus", "message": "x"}, _ctx())
    assert result.is_error
    assert "cannot reach cabal" in result.error


async def test_direct_message_reply_is_reported() -> None:
    reply = {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "hello"}]}
    handler, _ = _handler(_ok({"message": reply}))
    data = _data(await handler.dispatch("send", {"agent": "wright-secundus", "message": "hi"}, _ctx()))
    assert data == {"outcome": "replied", "agent": "wright-secundus", "context_id": data["context_id"], "reply": "hello"}


# ---- grants -------------------------------------------------------------


async def test_no_token_for_the_agent_refuses_without_a_call() -> None:
    handler, seen = _handler(_ok({}))
    result = await handler.dispatch("send", {"agent": "prudence", "message": "x"}, _ctx())
    assert result.is_error
    assert "no token for 'prudence'" in result.error
    assert seen == []


@pytest.mark.parametrize("agent", ["", "../admin", "Wright", "a/b", 7])
async def test_bad_agent_names_are_refused(agent: Any) -> None:
    handler, seen = _handler(_ok({}))
    result = await handler.dispatch("task", {"agent": agent, "task_id": "t"}, _ctx())
    assert result.is_error
    assert seen == []


async def test_cabal_refusal_is_reported_without_the_token() -> None:
    handler, _ = _handler(lambda r: httpx.Response(403, json={"detail": "revoked"}))
    result = await handler.dispatch("task", {"agent": "wright-secundus", "task_id": "t"}, _ctx())
    assert result.is_error
    assert "HTTP 403 revoked" in result.error
    assert TOKEN not in result.error


async def test_jsonrpc_error_is_reported_with_its_code() -> None:
    def fn(request: httpx.Request) -> httpx.Response:
        rid = json.loads(request.content)["id"]
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": rid, "error": {"code": -32001, "message": "Task not found"}}
        )

    handler, _ = _handler(fn)
    result = await handler.dispatch("task", {"agent": "wright-secundus", "task_id": "t"}, _ctx())
    assert result.is_error
    assert "Task not found (code -32001)" in result.error


async def test_no_cabal_url_is_a_config_error() -> None:
    handler = CabalHandler(base_url=None)
    result = await handler.dispatch("agents", {}, _ctx())
    assert result.is_error
    assert "LIMINAL_CABAL_A2A_URL" in result.error


# ---- agents -------------------------------------------------------------


async def test_agents_lists_only_credentialed_personas_with_cards() -> None:
    def fn(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/agents/wright-secundus/.well-known/agent-card.json":
            return httpx.Response(200, json={"name": "wright-secundus", "description": "a coder"})
        return httpx.Response(404)

    handler, seen = _handler(fn)
    creds = {"CABAL_TOKEN_WRIGHT_SECUNDUS": "a", "CABAL_TOKEN_GONE": "b"}
    data = _data(await handler.dispatch("agents", {}, _ctx(creds)))
    assert data["agents"] == [
        {"agent": "gone", "card_error": "card returned HTTP 404"},
        {"agent": "wright-secundus", "name": "wright-secundus", "description": "a coder"},
    ]
    assert all(r.method == "GET" for r in seen)


# ---- task, tasks, answer, cancel ---------------------------------------


async def test_task_reads_one_task() -> None:
    handler, seen = _handler(_ok(_task("TASK_STATE_COMPLETED")))
    data = _data(await handler.dispatch("task", {"agent": "wright-secundus", "task_id": "t-1"}, _ctx()))
    assert data["state"] == "completed"
    body = json.loads(seen[0].content)
    assert body["method"] == "GetTask"
    assert body["params"] == {"id": "t-1"}


async def test_tasks_passes_filters_in_v1_form() -> None:
    handler, seen = _handler(_ok({"tasks": [_task()], "nextPageToken": "", "pageSize": 1, "totalSize": 1}))
    data = _data(
        await handler.dispatch(
            "tasks", {"agent": "wright-secundus", "context_id": "c-1", "state": "input-required"}, _ctx()
        )
    )
    assert data["total"] == 1
    assert data["tasks"][0]["task_id"] == "t-1"
    params = json.loads(seen[0].content)["params"]
    assert params == {"contextId": "c-1", "status": "TASK_STATE_INPUT_REQUIRED"}


async def test_answer_continues_the_named_task() -> None:
    handler, seen = _handler(_ok({"task": _task("TASK_STATE_SUBMITTED")}))
    data = _data(
        await handler.dispatch("answer", {"agent": "wright-secundus", "task_id": "t-1", "text": "use option B"}, _ctx())
    )
    assert data["state"] == "submitted"
    msg = json.loads(seen[0].content)["params"]["message"]
    assert msg["taskId"] == "t-1"
    assert msg["parts"] == [{"text": "use option B"}]


async def test_cancel_calls_cancel_task() -> None:
    handler, seen = _handler(_ok(_task("TASK_STATE_CANCELED")))
    data = _data(await handler.dispatch("cancel", {"agent": "wright-secundus", "task_id": "t-1"}, _ctx()))
    assert data["state"] == "canceled"
    assert json.loads(seen[0].content)["method"] == "CancelTask"


async def test_missing_task_id_is_refused() -> None:
    handler, seen = _handler(_ok({}))
    result = await handler.dispatch("task", {"agent": "wright-secundus"}, _ctx())
    assert result.is_error
    assert "'task_id'" in result.error
    assert seen == []


async def test_answer_reports_a_direct_message_reply() -> None:
    reply = {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "noted"}]}
    handler, _ = _handler(_ok({"message": reply}))
    data = _data(await handler.dispatch("answer", {"agent": "wright-secundus", "task_id": "t-1", "text": "B"}, _ctx()))
    assert data == {"outcome": "replied", "agent": "wright-secundus", "reply": "noted"}


async def test_answer_with_neither_task_nor_message_is_a_failure() -> None:
    handler, _ = _handler(_ok({}))
    result = await handler.dispatch("answer", {"agent": "wright-secundus", "task_id": "t-1", "text": "B"}, _ctx())
    assert result.is_error
    assert "neither a task nor a message" in result.error
