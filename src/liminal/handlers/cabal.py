"""cabal — send work to cabal's personas from a person's own agent (liminal#189).

A local coding agent (Claude Code, goose, pi) speaks MCP, not A2A. This handler
is its way into cabal: it lists the personas the caller may send to, sends a
task and returns at once, and lets the caller poll, answer and cancel. The calls
go to each persona's A2A v1.0 endpoint, `POST {cabal}/agents/{agent}/a2a`.

Tokens. cabal admits an outside agent by giving it one dispatch token per
persona (cabal `docs/outside-agents.md`). The handler reads them from the
caller's credential set, which liminal fetches from cabal's encrypted store for
(persona, "cabal"), one key per target:

    CABAL_TOKEN_<AGENT>    AGENT in upper snake: wright-secundus -> WRIGHT_SECUNDUS

The credential set is the caller's grant: `cabal.agents` lists exactly the
personas it holds a token for, and the handler never sends with any other.

Fire-and-collect. `send` always asks cabal to return immediately, so a task that
runs for an hour doesn't hold the MCP call open; the caller polls `task`.

Uncertain delivery. If the request may have reached cabal but no reply came
back (a read timeout, a dropped connection, a 5xx), the task may or may not exist.
The handler says so (`outcome: "uncertain"`) instead of guessing, and returns the
contextId the send carried (the caller's, or one generated when it gave none), so
`tasks(agent, context_id)` settles it.

Server config (environment, read once):
    LIMINAL_CABAL_A2A_URL     cabal's base URL for A2A calls (default LIMINAL_CABAL_URL)
    LIMINAL_CABAL_A2A_TIMEOUT seconds per call (default 30)
"""

from __future__ import annotations

import asyncio
import os
import re
import uuid
from typing import Any

import httpx
import structlog

from liminal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)

TOKEN_PREFIX = "CABAL_TOKEN_"
DEFAULT_TIMEOUT_SECONDS = 30.0
# A cabal bulletin name: lower case, digits and hyphens (`wright-secundus`).
_AGENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_STATE_PREFIX = "TASK_STATE_"

CARD = {
    "handler": "cabal",
    "required_scope": "cabal:dispatch",
    "description": "Send tasks to cabal's personas over A2A, then poll, answer or cancel them.",
    "tools": [
        {"name": "agents", "description": "List the personas this caller may send tasks to."},
        {"name": "send", "description": "Send a task to a persona; returns its id at once."},
        {"name": "task", "description": "Read a task's state, last status message and artifacts."},
        {"name": "tasks", "description": "List this caller's tasks on a persona, newest first."},
        {"name": "answer", "description": "Answer a task that stopped in input-required."},
        {"name": "cancel", "description": "Cancel a running task."},
    ],
    "activation": "always",
    "credential_keys": [f"{TOKEN_PREFIX}<AGENT>"],
    "labels": {"tier": "builtin"},
}


class CabalCallError(Exception):
    """A call cabal answered with an error, or one that never reached it."""


class UncertainDelivery(Exception):
    """The request may have reached cabal, but no answer came back."""


def token_key(agent: str) -> str:
    return TOKEN_PREFIX + agent.upper().replace("-", "_")


def agents_in(credentials: dict[str, str]) -> list[str]:
    """The personas a credential set holds tokens for, as bulletin names."""
    names = (
        k[len(TOKEN_PREFIX):].lower().replace("_", "-")
        for k, v in credentials.items()
        if k.startswith(TOKEN_PREFIX) and v
    )
    return sorted(n for n in names if _AGENT_RE.match(n))


def _state(raw: Any) -> str:
    """TASK_STATE_INPUT_REQUIRED -> input-required."""
    s = str(raw or "")
    if s.startswith(_STATE_PREFIX):
        s = s[len(_STATE_PREFIX):]
    return s.lower().replace("_", "-")


def _text(parts: Any) -> str:
    if not isinstance(parts, list):
        return ""
    return "\n".join(p["text"] for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str))


def summarize(task: dict[str, Any]) -> dict[str, Any]:
    """The parts of a v1.0 Task a caller acts on, text only."""
    status = task.get("status") or {}
    message = status.get("message") or {}
    out: dict[str, Any] = {
        "task_id": task.get("id"),
        "context_id": task.get("contextId"),
        "state": _state(status.get("state")),
        "updated": status.get("timestamp"),
        "status_message": _text(message.get("parts")),
    }
    artifacts = [
        {"name": a.get("name"), "text": _text(a.get("parts"))}
        for a in task.get("artifacts") or []
        if isinstance(a, dict)
    ]
    if artifacts:
        out["artifacts"] = artifacts
    meta = task.get("metadata") or {}
    group = meta.get("cabal_group")
    if group:
        out["group"] = group
    return out


class CabalHandler:
    def __init__(
        self,
        *,
        base_url: str | None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        http_client_factory: Any = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=httpx.Timeout(self.timeout_seconds))
        )

    # ---- protocol ------------------------------------------------------

    def capability_card(self) -> dict[str, Any]:
        return CARD

    def tools(self) -> list[ToolSpec]:
        agent = {"type": "string", "description": "The persona's bulletin name, as cabal.agents lists it."}
        task_id = {"type": "string", "description": "The id cabal.send returned."}
        return [
            ToolSpec(
                name="agents",
                description=(
                    "List the cabal personas you may send tasks to, with each one's description "
                    "from its agent card."
                ),
                input_schema={"type": "object", "properties": {}},
            ),
            ToolSpec(
                name="send",
                description=(
                    "Send a task to a persona. Returns at once with the task id and state; poll "
                    "cabal.task for progress. outcome 'uncertain' means the request may have "
                    "reached cabal without a reply: call cabal.tasks with the returned "
                    "context_id before sending again. Pass group to queue the task to whichever "
                    "member of that cabal group is idle next (agent must be a member)."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "agent": agent,
                        "message": {"type": "string", "description": "The brief, as text."},
                        "context_id": {
                            "type": "string",
                            "description": "Continue an earlier conversation with this persona.",
                        },
                        "group": {"type": "string", "description": "A cabal group name, e.g. 'wright'."},
                    },
                    "required": ["agent", "message"],
                },
            ),
            ToolSpec(
                name="task",
                description="Read one task: state, last status message, artifacts.",
                input_schema={
                    "type": "object",
                    "properties": {"agent": agent, "task_id": task_id},
                    "required": ["agent", "task_id"],
                },
            ),
            ToolSpec(
                name="tasks",
                description=(
                    "List the tasks you sent to a persona, newest status first. Filter by "
                    "context_id (to settle an uncertain send) or state (e.g. 'input-required')."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "agent": agent,
                        "context_id": {"type": "string"},
                        "state": {"type": "string"},
                        "page_size": {"type": "integer", "minimum": 1, "maximum": 100},
                    },
                    "required": ["agent"],
                },
            ),
            ToolSpec(
                name="answer",
                description=(
                    "Answer a task that stopped in input-required. cabal accepts this today for "
                    "group tasks (the answer re-queues the task to the next idle member); other "
                    "tasks are refused until cabal can pause one (cabal#145)."
                ),
                input_schema={
                    "type": "object",
                    "properties": {"agent": agent, "task_id": task_id, "text": {"type": "string"}},
                    "required": ["agent", "task_id", "text"],
                },
            ),
            ToolSpec(
                name="cancel",
                description="Cancel a running task.",
                input_schema={
                    "type": "object",
                    "properties": {"agent": agent, "task_id": task_id},
                    "required": ["agent", "task_id"],
                },
            ),
        ]

    async def dispatch(self, name: str, payload: dict[str, Any], ctx: Context) -> ToolResult:
        if not self.base_url:
            return ToolResult.failure(
                "cabal handler has no cabal URL: set LIMINAL_CABAL_A2A_URL (or LIMINAL_CABAL_URL) on the server"
            )
        try:
            if name == "agents":
                return await self._agents(ctx)
            agent = payload.get("agent")
            if not isinstance(agent, str) or not _AGENT_RE.match(agent):
                return ToolResult.failure("'agent' must be a persona's bulletin name (see cabal.agents)")
            token = ctx.credentials.get(token_key(agent))
            if not token:
                return ToolResult.failure(
                    f"you hold no token for {agent!r}; cabal.agents lists the personas you may call"
                )
            if name == "send":
                return await self._send(agent, token, payload)
            if name == "task":
                tid = _required_str(payload, "task_id")
                result = await self._rpc(agent, token, "GetTask", {"id": tid})
                return ToolResult.json(summarize(result))
            if name == "tasks":
                return await self._tasks(agent, token, payload)
            if name == "answer":
                tid = _required_str(payload, "task_id")
                text = _required_str(payload, "text")
                message = {
                    "messageId": str(uuid.uuid4()),
                    "taskId": tid,
                    "role": "ROLE_USER",
                    "parts": [{"text": text}],
                }
                result = await self._rpc(agent, token, "SendMessage", {"message": message})
                task = result.get("task")
                if isinstance(task, dict):
                    return ToolResult.json(summarize(task))
                reply = result.get("message")
                if isinstance(reply, dict):
                    # A persona may answer with a direct Message, as on send.
                    return ToolResult.json({"outcome": "replied", "agent": agent, "reply": _text(reply.get("parts"))})
                return ToolResult.failure(f"cabal answered SendMessage on {agent} with neither a task nor a message")
            if name == "cancel":
                tid = _required_str(payload, "task_id")
                result = await self._rpc(agent, token, "CancelTask", {"id": tid})
                return ToolResult.json(summarize(result))
        except _BadInput as exc:
            return ToolResult.failure(str(exc))
        except UncertainDelivery as exc:
            return ToolResult.failure(f"no answer from cabal, outcome unknown: {exc}")
        except CabalCallError as exc:
            return ToolResult.failure(str(exc))
        return ToolResult.failure(f"unknown tool {name!r}")

    # ---- tools ---------------------------------------------------------

    async def _agents(self, ctx: Context) -> ToolResult:
        names = agents_in(ctx.credentials)
        async with self._client_factory() as client:
            cards = await asyncio.gather(*(self._card(client, n) for n in names))
        return ToolResult.json({"agents": cards})

    async def _card(self, client: httpx.AsyncClient, agent: str) -> dict[str, Any]:
        url = f"{self.base_url}/agents/{agent}/.well-known/agent-card.json"
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            return {"agent": agent, "card_error": f"card unreachable ({type(exc).__name__})"}
        if resp.status_code != 200:
            return {"agent": agent, "card_error": f"card returned HTTP {resp.status_code}: {_detail(resp)}".rstrip(": ")}
        try:
            card = resp.json()
        except ValueError:
            return {"agent": agent, "card_error": "card is not JSON"}
        return {"agent": agent, "name": card.get("name"), "description": card.get("description")}

    async def _send(self, agent: str, token: str, payload: dict[str, Any]) -> ToolResult:
        text = _required_str(payload, "message")
        context_id = payload.get("context_id") or str(uuid.uuid4())
        if not isinstance(context_id, str):
            raise _BadInput("'context_id' must be a string")
        message = {
            "messageId": str(uuid.uuid4()),
            "contextId": context_id,
            "role": "ROLE_USER",
            "parts": [{"text": text}],
        }
        params: dict[str, Any] = {"message": message, "configuration": {"returnImmediately": True}}
        group = payload.get("group")
        if group is not None:
            if not isinstance(group, str) or not group:
                raise _BadInput("'group' must be a non-empty string")
            params["metadata"] = {"cabal_group": group}
        try:
            result = await self._rpc(agent, token, "SendMessage", params)
        except UncertainDelivery as exc:
            log.warning("cabal.send_uncertain", agent=agent, context_id=context_id, reason=str(exc))
            return ToolResult.json(
                {
                    "outcome": "uncertain",
                    "agent": agent,
                    "context_id": context_id,
                    "reason": str(exc),
                    "next": "call cabal.tasks with this agent and context_id before sending again",
                }
            )
        task = result.get("task")
        if not isinstance(task, dict):
            # A persona may answer with a direct Message instead of a Task.
            reply = result.get("message") or {}
            return ToolResult.json(
                {"outcome": "replied", "agent": agent, "context_id": context_id, "reply": _text(reply.get("parts"))}
            )
        log.info("cabal.sent", agent=agent, task_id=task.get("id"), group=group)
        return ToolResult.json({"outcome": "sent", "agent": agent, **summarize(task)})

    async def _tasks(self, agent: str, token: str, payload: dict[str, Any]) -> ToolResult:
        params: dict[str, Any] = {}
        if payload.get("context_id"):
            params["contextId"] = str(payload["context_id"])
        if payload.get("state"):
            params["status"] = _STATE_PREFIX + str(payload["state"]).upper().replace("-", "_")
        if payload.get("page_size"):
            params["pageSize"] = payload["page_size"]
        result = await self._rpc(agent, token, "ListTasks", params)
        tasks = [summarize(t) for t in result.get("tasks") or [] if isinstance(t, dict)]
        return ToolResult.json({"tasks": tasks, "total": result.get("totalSize", len(tasks))})

    # ---- transport -----------------------------------------------------

    async def _rpc(self, agent: str, token: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/agents/{agent}/a2a"
        body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
        headers = {"Authorization": f"Bearer {token}", "A2A-Version": "1.0"}
        log.debug("cabal.rpc", agent=agent, method=method)
        async with self._client_factory() as client:
            try:
                resp = await client.post(url, json=body, headers=headers)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                # Never left this host: definitely not delivered.
                raise CabalCallError(f"cannot reach cabal at {self.base_url} ({type(exc).__name__})") from exc
            except httpx.HTTPError as exc:
                # Sent, maybe received; no reply. Only the exception class goes
                # back: httpx text can carry the URL and headers.
                raise UncertainDelivery(type(exc).__name__) from exc
        if resp.status_code in (401, 403):
            raise CabalCallError(f"cabal refused {method} on {agent}: HTTP {resp.status_code} {_detail(resp)}")
        if resp.status_code >= 500 and method == "SendMessage":
            raise UncertainDelivery(f"HTTP {resp.status_code}")
        try:
            reply = resp.json()
        except ValueError as exc:
            raise CabalCallError(f"cabal answered {method} with HTTP {resp.status_code}, not JSON") from exc
        if not isinstance(reply, dict):
            raise CabalCallError(f"cabal answered {method} with HTTP {resp.status_code}: {_detail(resp)}")
        err = reply.get("error")
        if isinstance(err, dict):
            raise CabalCallError(f"cabal {method} on {agent}: {err.get('message')} (code {err.get('code')})")
        if resp.status_code != 200 or not isinstance(reply.get("result"), dict):
            raise CabalCallError(f"cabal answered {method} with HTTP {resp.status_code}: {_detail(resp)}")
        return reply["result"]


class _BadInput(ValueError):
    pass


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _BadInput(f"{key!r} must be a non-empty string")
    return value


def _detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("error") or "")[:300]
    return ""


def get_handler() -> Handler:
    """Entry-point factory, configured from the environment."""
    base = os.environ.get("LIMINAL_CABAL_A2A_URL") or os.environ.get("LIMINAL_CABAL_URL")
    timeout = float(os.environ.get("LIMINAL_CABAL_A2A_TIMEOUT") or DEFAULT_TIMEOUT_SECONDS)
    return CabalHandler(base_url=base, timeout_seconds=timeout)
