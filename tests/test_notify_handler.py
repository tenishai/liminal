"""notify handler — transport routing, webhook delivery, SSRF defense."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from limenal.handlers.notify import (
    LEVELS,
    NotifyError,
    NotifyHandler,
    StdoutTransport,
    Transport,
    WebhookTransport,
)
from limenal.protocol import Context


def _ctx(
    *,
    credentials: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Context:
    return Context(
        identity="rook",
        agent_name="rook-primus",
        credentials=credentials or {},
        extra=extra or {},
    )


def _webhook(
    handler_fn,
    *,
    dns_map: dict[str, list[str]] | None = None,
) -> WebhookTransport:
    def resolver(host: str) -> list[str]:
        return (dns_map or {}).get(host, ["93.184.216.34"])  # default public IP

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler_fn), timeout=httpx.Timeout(5.0)
        )

    return WebhookTransport(
        http_client_factory=factory,
        dns_resolver=resolver,
    )


# ---- transport routing -------------------------------------------------


@pytest.mark.asyncio
async def test_default_transports_are_webhook_and_stdout() -> None:
    """Out of the box NotifyHandler ships with both default transports
    so the operator can use webhook for real notifications + stdout
    for dev/audit without configuring anything."""
    handler = NotifyHandler()
    assert "webhook" in handler.transports
    assert "stdout" in handler.transports
    assert handler.default_transport == "webhook"


@pytest.mark.asyncio
async def test_list_transports_returns_credential_keys() -> None:
    handler = NotifyHandler()
    result = await handler.dispatch("list_transports", {}, _ctx())
    payload = result.content[0]["data"]
    assert payload["default"] == "webhook"
    by_name = {t["name"]: t for t in payload["transports"]}
    assert by_name["webhook"]["credential_keys"] == ["NOTIFY_WEBHOOK_URL"]
    # stdout needs nothing from the operator
    assert by_name["stdout"]["credential_keys"] == []


@pytest.mark.asyncio
async def test_capability_card_unions_transport_credential_keys() -> None:
    """When more transports are registered, the card's credential_keys
    should be the union — so the operator knows what to provision."""

    class _FakeSlack(Transport):
        name = "slack"

        @property
        def credential_keys(self) -> list[str]:
            return ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"]

        async def send(self, **kwargs):
            return {}

    handler = NotifyHandler(
        transports={"webhook": WebhookTransport(), "slack": _FakeSlack()},
    )
    card = handler.capability_card()
    assert set(card["credential_keys"]) == {
        "NOTIFY_WEBHOOK_URL",
        "SLACK_BOT_TOKEN",
        "SLACK_APP_TOKEN",
    }


@pytest.mark.asyncio
async def test_unknown_transport_returns_structured_failure() -> None:
    handler = NotifyHandler()
    result = await handler.dispatch(
        "send",
        {"message": "hi", "transport": "carrier-pigeon"},
        _ctx(),
    )
    assert result.is_error is True
    assert "carrier-pigeon" in result.error
    assert "webhook" in result.error  # lists available


# ---- input validation --------------------------------------------------


@pytest.mark.asyncio
async def test_empty_message_refused() -> None:
    handler = NotifyHandler()
    for bad in ("", "   ", None):
        result = await handler.dispatch("send", {"message": bad}, _ctx())
        assert result.is_error is True


@pytest.mark.asyncio
async def test_invalid_level_refused() -> None:
    handler = NotifyHandler()
    result = await handler.dispatch(
        "send", {"message": "hi", "level": "EMERGENCY"}, _ctx()
    )
    assert result.is_error is True
    assert all(lvl in result.error for lvl in LEVELS)


@pytest.mark.asyncio
async def test_non_string_title_refused() -> None:
    handler = NotifyHandler()
    result = await handler.dispatch(
        "send", {"message": "hi", "title": ["not", "a", "string"]}, _ctx()
    )
    assert result.is_error is True


# ---- webhook delivery (happy path) -------------------------------------


@pytest.mark.asyncio
async def test_webhook_posts_json_body_with_persona_metadata() -> None:
    captured: list[httpx.Request] = []

    def handler_fn(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"ok": True})

    handler = NotifyHandler(transports={"webhook": _webhook(handler_fn)})
    result = await handler.dispatch(
        "send",
        {
            "message": "long job done",
            "level": "info",
            "title": "Build #42",
        },
        _ctx(credentials={"NOTIFY_WEBHOOK_URL": "https://example.com/hook"}),
    )
    assert result.is_error is False
    payload = result.content[0]["data"]
    assert payload["ok"] is True
    assert payload["status"] == 200

    assert len(captured) == 1
    body = json.loads(captured[0].read())
    assert body == {
        "title": "Build #42",
        "message": "long job done",
        "level": "info",
        "persona": "rook",
        "agent_name": "rook-primus",
    }


@pytest.mark.asyncio
async def test_webhook_url_from_extra_when_credential_absent() -> None:
    """The extra-key path is the test-and-public-URL convenience."""
    captured: list[str] = []

    def handler_fn(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(204)

    handler = NotifyHandler(transports={"webhook": _webhook(handler_fn)})
    result = await handler.dispatch(
        "send",
        {"message": "hi"},
        _ctx(extra={"notify.webhook_url": "https://ntfy.example/topic"}),
    )
    assert result.is_error is False
    assert captured == ["https://ntfy.example/topic"]


@pytest.mark.asyncio
async def test_credential_url_wins_over_extra_url() -> None:
    captured: list[str] = []

    def handler_fn(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(204)

    handler = NotifyHandler(transports={"webhook": _webhook(handler_fn)})
    await handler.dispatch(
        "send",
        {"message": "hi"},
        _ctx(
            credentials={"NOTIFY_WEBHOOK_URL": "https://creds.example/hook"},
            extra={"notify.webhook_url": "https://extra.example/hook"},
        ),
    )
    assert captured == ["https://creds.example/hook"]


@pytest.mark.asyncio
async def test_webhook_no_url_configured_returns_failure() -> None:
    handler = NotifyHandler(
        transports={"webhook": _webhook(lambda req: httpx.Response(200))}
    )
    result = await handler.dispatch("send", {"message": "x"}, _ctx())
    assert result.is_error is True
    assert "URL not configured" in result.error


# ---- webhook SSRF defense ---------------------------------------------


@pytest.mark.asyncio
async def test_webhook_rejects_loopback_resolution() -> None:
    handler = NotifyHandler(
        transports={
            "webhook": _webhook(
                lambda req: httpx.Response(200),
                dns_map={"sneaky.test": ["127.0.0.1"]},
            )
        }
    )
    result = await handler.dispatch(
        "send",
        {"message": "x"},
        _ctx(extra={"notify.webhook_url": "https://sneaky.test/hook"}),
    )
    assert result.is_error is True
    assert "127.0.0.1" in result.error or "denied network" in result.error


@pytest.mark.asyncio
async def test_webhook_rejects_metadata_service() -> None:
    handler = NotifyHandler(
        transports={
            "webhook": _webhook(
                lambda req: httpx.Response(200),
                dns_map={"meta.test": ["169.254.169.254"]},
            )
        }
    )
    result = await handler.dispatch(
        "send",
        {"message": "x"},
        _ctx(extra={"notify.webhook_url": "https://meta.test/hook"}),
    )
    assert result.is_error is True


@pytest.mark.asyncio
async def test_webhook_rejects_non_http_scheme() -> None:
    handler = NotifyHandler(
        transports={"webhook": _webhook(lambda req: httpx.Response(200))}
    )
    result = await handler.dispatch(
        "send",
        {"message": "x"},
        _ctx(extra={"notify.webhook_url": "ftp://example.com/hook"}),
    )
    assert result.is_error is True
    assert "scheme" in result.error


@pytest.mark.asyncio
async def test_webhook_respects_per_persona_allowlist() -> None:
    handler = NotifyHandler(
        transports={"webhook": _webhook(lambda req: httpx.Response(200))}
    )
    result = await handler.dispatch(
        "send",
        {"message": "x"},
        _ctx(
            extra={
                "notify.webhook_url": "https://malicious.test/hook",
                "notify.allowed_hosts": ["company-slack.example"],
            }
        ),
    )
    assert result.is_error is True
    assert "allowlist" in result.error


# ---- per-call transport override ---------------------------------------


@pytest.mark.asyncio
async def test_send_transport_arg_overrides_default() -> None:
    """The persona can pick transport per call when more than one is wired."""
    calls = {"webhook": 0, "fake": 0}

    def hook_fn(request: httpx.Request) -> httpx.Response:
        calls["webhook"] += 1
        return httpx.Response(200)

    class _Fake(Transport):
        name = "fake"

        @property
        def credential_keys(self):
            return []

        async def send(self, **kwargs):
            calls["fake"] += 1
            return {"transport": "fake", "ok": True}

    handler = NotifyHandler(
        transports={"webhook": _webhook(hook_fn), "fake": _Fake()},
        default_transport="webhook",
    )
    await handler.dispatch(
        "send",
        {"message": "via fake", "transport": "fake"},
        _ctx(),
    )
    assert calls == {"webhook": 0, "fake": 1}


@pytest.mark.asyncio
async def test_ctx_extra_transport_used_when_payload_omits() -> None:
    calls = {"fake": 0}

    class _Fake(Transport):
        name = "fake"

        @property
        def credential_keys(self):
            return []

        async def send(self, **kwargs):
            calls["fake"] += 1
            return {"ok": True}

    handler = NotifyHandler(
        transports={
            "webhook": _webhook(lambda r: httpx.Response(200)),
            "fake": _Fake(),
        },
        default_transport="webhook",
    )
    await handler.dispatch(
        "send",
        {"message": "x"},
        _ctx(extra={"notify.transport": "fake"}),
    )
    assert calls == {"fake": 1}


# ---- transport.send raises NotifyError → structured failure -----------


@pytest.mark.asyncio
async def test_transport_notify_error_becomes_tool_failure() -> None:
    class _Crash(Transport):
        name = "crash"

        @property
        def credential_keys(self):
            return []

        async def send(self, **kwargs):
            raise NotifyError("backend unreachable")

    handler = NotifyHandler(
        transports={"crash": _Crash()},
        default_transport="crash",
    )
    result = await handler.dispatch("send", {"message": "x"}, _ctx())
    assert result.is_error is True
    assert "backend unreachable" in result.error


# ---- entry-point + card ------------------------------------------------


def test_handler_registered_in_entry_points() -> None:
    from limenal.registry import discover_handlers

    registry = discover_handlers()
    record = registry.get("notify")
    assert record is not None
    assert record.card.handler == "notify"
    assert {t.name for t in record.card.tools} == {"send", "list_transports"}


# ---- stdout transport (Phase MM) ---------------------------------------


@pytest.mark.asyncio
async def test_stdout_transport_writes_to_stream() -> None:
    """The persona's notification line lands in the provided stream
    with persona, agent_name, level, and message visible."""
    import io

    buf = io.StringIO()
    handler = NotifyHandler(
        transports={"stdout": StdoutTransport(stream=buf, timestamp=False)},
        default_transport="stdout",
    )
    result = await handler.dispatch(
        "send",
        {"message": "build complete", "level": "info", "title": "Build #42"},
        _ctx(),
    )
    assert result.is_error is False
    out = buf.getvalue()
    assert "[INFO]" in out
    assert "[rook:rook-primus]" in out
    assert "Build #42:" in out
    assert "build complete" in out


@pytest.mark.asyncio
async def test_stdout_transport_omits_title_when_absent() -> None:
    import io

    buf = io.StringIO()
    handler = NotifyHandler(
        transports={"stdout": StdoutTransport(stream=buf, timestamp=False)},
        default_transport="stdout",
    )
    await handler.dispatch("send", {"message": "x"}, _ctx())
    line = buf.getvalue().rstrip("\n")
    # No `<title>:` between the agent tag and the message
    assert line.endswith("[rook:rook-primus] x")


@pytest.mark.asyncio
async def test_stdout_transport_level_appears_uppercase() -> None:
    import io

    buf = io.StringIO()
    handler = NotifyHandler(
        transports={"stdout": StdoutTransport(stream=buf, timestamp=False)},
        default_transport="stdout",
    )
    await handler.dispatch(
        "send", {"message": "x", "level": "warning"}, _ctx()
    )
    assert "[WARNING]" in buf.getvalue()


@pytest.mark.asyncio
async def test_stdout_transport_with_timestamp_prefix() -> None:
    """Default timestamp=True prepends an ISO8601 UTC timestamp."""
    import io
    import re

    buf = io.StringIO()
    handler = NotifyHandler(
        transports={"stdout": StdoutTransport(stream=buf, timestamp=True)},
        default_transport="stdout",
    )
    await handler.dispatch("send", {"message": "x"}, _ctx())
    line = buf.getvalue()
    # ISO 8601 prefix like 2026-06-11T19:42:13+00:00
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)


@pytest.mark.asyncio
async def test_stdout_transport_no_credentials_required() -> None:
    """The transport never reads ctx.credentials. A completely empty
    Context still produces a notification — important for dev where
    the operator hasn't set up any secrets yet."""
    import io

    buf = io.StringIO()
    handler = NotifyHandler(
        transports={"stdout": StdoutTransport(stream=buf, timestamp=False)},
        default_transport="stdout",
    )
    result = await handler.dispatch(
        "send",
        {"message": "no creds needed"},
        _ctx(credentials={}, extra={}),
    )
    assert result.is_error is False
    assert "no creds needed" in buf.getvalue()


@pytest.mark.asyncio
async def test_stdout_transport_selected_per_call() -> None:
    """Same handler instance with both transports; persona picks stdout
    per call without operator config."""
    import io

    buf = io.StringIO()
    webhook_calls = {"n": 0}

    def hook_fn(request: httpx.Request) -> httpx.Response:
        webhook_calls["n"] += 1
        return httpx.Response(200)

    handler = NotifyHandler(
        transports={
            "webhook": _webhook(hook_fn),
            "stdout": StdoutTransport(stream=buf, timestamp=False),
        },
        default_transport="webhook",
    )
    # Default would be webhook; pick stdout per-call instead
    await handler.dispatch(
        "send",
        {"message": "via stdout", "transport": "stdout"},
        _ctx(),
    )
    assert webhook_calls["n"] == 0
    assert "via stdout" in buf.getvalue()
