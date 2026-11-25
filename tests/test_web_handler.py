"""web handler — allowlist, SSRF defense, fetch, head.

Uses httpx.MockTransport for the outbound calls and a stub
`dns_resolver` to control IP resolution deterministically.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from liminal.handlers.web import (
    WebConfig,
    WebHandler,
    _host_in_allowlist,
    _pin_request,
)
from liminal.protocol import Context


def _ctx(extra: dict[str, Any] | None = None) -> Context:
    return Context(
        identity="rook",
        agent_name="rook-primus",
        credentials={},
        extra=extra or {},
    )


def _build_handler(
    *,
    mock: httpx.MockTransport,
    allowed_hosts: list[str] | None = None,
    dns_map: dict[str, list[str]] | None = None,
    max_response_bytes: int = 1_000_000,
    allowed_content_types: set[str] | None = None,
) -> WebHandler:
    cfg = WebConfig(
        allowed_hosts=allowed_hosts or ["*"],
        max_response_bytes=max_response_bytes,
    )
    if allowed_content_types is not None:
        cfg.allowed_content_types = allowed_content_types

    def resolver(host: str) -> list[str]:
        return (dns_map or {"default-public.invalid": ["93.184.216.34"]}).get(
            host, ["93.184.216.34"]
        )

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=mock, timeout=httpx.Timeout(5.0))

    return WebHandler(
        default_config=cfg,
        http_client_factory=factory,
        dns_resolver=resolver,
    )


# ---- allowlist matcher ----------------------------------------------------


def test_allowlist_wildcard_matches_everything() -> None:
    assert _host_in_allowlist("example.com", ["*"])
    assert _host_in_allowlist("anything.tld", ["*"])


def test_allowlist_exact_match() -> None:
    assert _host_in_allowlist("api.example.com", ["api.example.com"])
    assert not _host_in_allowlist("api.example.com", ["api.example.org"])


def test_allowlist_glob_prefix() -> None:
    assert _host_in_allowlist("api.example.com", ["*.example.com"])
    assert _host_in_allowlist("docs.api.example.com", ["*.example.com"])


def test_allowlist_suffix_match() -> None:
    """Bare domain matches its subdomains as a convenience."""
    assert _host_in_allowlist("api.example.com", ["example.com"])
    assert _host_in_allowlist("example.com", ["example.com"])
    assert not _host_in_allowlist("malicious-example.com", ["example.com"])


def test_allowlist_case_insensitive() -> None:
    assert _host_in_allowlist("Example.com", ["example.com"])
    assert _host_in_allowlist("example.com", ["EXAMPLE.com"])


# ---- URL pre-flight refusals ---------------------------------------------


@pytest.mark.asyncio
async def test_rejects_non_http_scheme() -> None:
    handler = _build_handler(mock=httpx.MockTransport(lambda _: httpx.Response(200)))
    result = await handler.dispatch(
        "fetch", {"url": "ftp://example.com/x"}, _ctx()
    )
    assert result.is_error is True
    assert "scheme" in result.error


@pytest.mark.asyncio
async def test_rejects_empty_url() -> None:
    handler = _build_handler(mock=httpx.MockTransport(lambda _: httpx.Response(200)))
    result = await handler.dispatch("fetch", {}, _ctx())
    assert result.is_error is True
    assert "url" in result.error


@pytest.mark.asyncio
async def test_rejects_host_not_in_allowlist() -> None:
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        allowed_hosts=["example.com"],
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://malicious.org/"}, _ctx()
    )
    assert result.is_error is True
    assert "allowlist" in result.error


# ---- SSRF defense ---------------------------------------------------------


@pytest.mark.asyncio
async def test_rejects_loopback_resolution() -> None:
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"sneaky.test": ["127.0.0.1"]},
        allowed_hosts=["*"],
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://sneaky.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "127.0.0.1" in result.error or "denied network" in result.error


@pytest.mark.asyncio
async def test_rejects_metadata_service() -> None:
    """169.254.169.254 is the AWS/Azure/GCP metadata service — classic SSRF pivot."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"metadata.test": ["169.254.169.254"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://metadata.test/latest/meta-data/"}, _ctx()
    )
    assert result.is_error is True
    assert "169.254" in result.error or "denied network" in result.error


@pytest.mark.asyncio
async def test_rejects_rfc1918_resolution() -> None:
    """Even a public-looking host can't resolve to a private 10.x address."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"internal-host.test": ["10.0.0.1"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://internal-host.test/"}, _ctx()
    )
    assert result.is_error is True


@pytest.mark.asyncio
async def test_rejects_dns_resolution_failure() -> None:
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"resolves.fine": ["93.184.216.34"]},
    )
    # Host not in dns_map; resolver returns its default — let's make it
    # explicitly empty by overriding
    handler.dns_resolver = lambda h: []  # type: ignore[assignment]
    result = await handler.dispatch(
        "fetch", {"url": "https://no-such-host.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "resolve" in result.error


# ---- fetch happy path -----------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_returns_text_content() -> None:
    captured = {"req": None}

    def handler_fn(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(
            200,
            headers={"content-type": "text/plain; charset=utf-8"},
            content=b"Hello, world!",
        )

    handler = _build_handler(mock=httpx.MockTransport(handler_fn))
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/"}, _ctx()
    )
    assert result.is_error is False
    payload = result.content[0]["data"]
    assert payload["status"] == 200
    assert payload["content_type"] == "text/plain"
    assert payload["text"] == "Hello, world!"
    assert payload["truncated"] is False
    assert payload["bytes"] == 13


@pytest.mark.asyncio
async def test_fetch_returns_json_content() -> None:
    def handler_fn(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"answer": 42}',
        )

    handler = _build_handler(mock=httpx.MockTransport(handler_fn))
    result = await handler.dispatch(
        "fetch", {"url": "https://api.example.com/"}, _ctx()
    )
    assert result.is_error is False
    payload = result.content[0]["data"]
    assert payload["text"] == '{"answer": 42}'


# ---- size cap ------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_truncates_at_size_cap() -> None:
    big = b"x" * 5000

    def handler_fn(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=big,
        )

    handler = _build_handler(
        mock=httpx.MockTransport(handler_fn),
        max_response_bytes=1024,
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/"}, _ctx()
    )
    payload = result.content[0]["data"]
    assert payload["bytes"] <= 1024
    assert payload["truncated"] is True


@pytest.mark.asyncio
async def test_max_bytes_payload_cap_capped_by_handler_config() -> None:
    """The caller can REDUCE the cap but not raise it above handler config."""
    big = b"x" * 5000

    def handler_fn(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=big,
        )

    handler = _build_handler(
        mock=httpx.MockTransport(handler_fn),
        max_response_bytes=2000,
    )
    # Caller asks for 99999 — handler still caps at its 2000
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/", "max_bytes": 99999}, _ctx()
    )
    payload = result.content[0]["data"]
    assert payload["bytes"] <= 2000


def _text_handler(body: bytes) -> WebHandler:
    def handler_fn(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/plain"}, content=body
        )

    return _build_handler(mock=httpx.MockTransport(handler_fn))


@pytest.mark.asyncio
@pytest.mark.parametrize("max_bytes", ["abc", "10", 1.5, True, [10]])
async def test_non_integer_max_bytes_is_refused_naming_the_field(max_bytes: Any) -> None:
    """#193: "abc" used to reach the agent as "web.fetch raised ValueError"."""
    handler = _text_handler(b"hello")
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/", "max_bytes": max_bytes}, _ctx()
    )
    assert result.is_error is True
    assert "'max_bytes' must be an integer" in result.error


@pytest.mark.asyncio
@pytest.mark.parametrize("max_bytes", [-5, 0])
async def test_max_bytes_below_one_clamps_to_one(max_bytes: int) -> None:
    handler = _text_handler(b"hello")
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/", "max_bytes": max_bytes}, _ctx()
    )
    assert result.is_error is False, result.error
    payload = result.content[0]["data"]
    assert payload["bytes"] == 1
    assert payload["truncated"] is True


@pytest.mark.asyncio
async def test_null_max_bytes_uses_the_handler_cap() -> None:
    handler = _text_handler(b"hello")
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/", "max_bytes": None}, _ctx()
    )
    assert result.is_error is False, result.error
    assert result.content[0]["data"]["truncated"] is False


# ---- content-type filter -------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_refuses_image_by_default() -> None:
    def handler_fn(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "image/png"},
            content=b"PNG-bytes-not-real",
        )

    handler = _build_handler(mock=httpx.MockTransport(handler_fn))
    result = await handler.dispatch(
        "fetch", {"url": "https://example.com/cat.png"}, _ctx()
    )
    assert result.is_error is True
    assert "content-type" in result.error


# ---- HEAD --------------------------------------------------------------


@pytest.mark.asyncio
async def test_head_returns_headers() -> None:
    def handler_fn(request: httpx.Request) -> httpx.Response:
        assert request.method == "HEAD"
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "etag": "abc123",
            },
        )

    handler = _build_handler(mock=httpx.MockTransport(handler_fn))
    result = await handler.dispatch(
        "head", {"url": "https://example.com/"}, _ctx()
    )
    payload = result.content[0]["data"]
    assert payload["status"] == 200
    assert payload["headers"]["etag"] == "abc123"


# ---- per-persona allowlist override -----------------------------------


@pytest.mark.asyncio
async def test_per_persona_allowlist_via_ctx_extra() -> None:
    """When ctx.extra carries a tighter per-persona allowlist, it wins
    over the handler default. Cabal forwards this via task metadata."""

    def handler_fn(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"ok"
        )

    handler = _build_handler(
        mock=httpx.MockTransport(handler_fn),
        allowed_hosts=["*"],
    )
    ctx = _ctx(extra={"web.allowed_hosts": ["docs.example.com"]})
    # Allowed
    r1 = await handler.dispatch(
        "fetch", {"url": "https://docs.example.com/page"}, ctx
    )
    assert r1.is_error is False
    # Denied by per-persona allowlist
    r2 = await handler.dispatch("fetch", {"url": "https://other.test/"}, ctx)
    assert r2.is_error is True
    assert "allowlist" in r2.error


# ---- protocol conformance + entry-point discovery -------------------


def test_handler_is_registered_in_entry_points() -> None:
    from liminal.registry import discover_handlers

    registry = discover_handlers()
    record = registry.get("web")
    assert record is not None
    assert record.card.handler == "web"
    assert any(t.name == "fetch" for t in record.card.tools)


def test_capability_card_advertises_no_credentials() -> None:
    """Web doesn't need a token to fetch public URLs."""
    from liminal.handlers.web import get_handler

    card = get_handler().capability_card()
    assert card["credential_keys"] == []


# ---- Phase 5: DNS-rebinding protection -----------------------------------


@pytest.mark.asyncio
async def test_dns_rebinding_blocked_via_ip_pin(tmp_path) -> None:
    """Attacker's host resolves to a public IP on first check, then to a
    metadata IP at connect time. With IP pinning, we connect to the
    validated IP regardless of what DNS returns later.

    We simulate this by injecting a resolver that returns a public IP,
    and a mock HTTP transport that captures the URL httpx actually
    connects to. The request URL should contain the public IP (pinned),
    not the original hostname.
    """
    import httpx

    from liminal.handlers.web import WebConfig, WebHandler

    connect_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        connect_urls.append(str(request.url))
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    handler_obj = WebHandler(
        default_config=WebConfig(allowed_hosts=["evil.example.com"]),
        http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
        dns_resolver=lambda host: ["8.8.8.8"],  # returns safe public IP
    )

    from liminal.protocol import Context

    ctx = Context(identity="test", agent_name="test", credentials={}, extra={})
    result = await handler_obj.dispatch(
        "fetch", {"url": "http://evil.example.com/data"}, ctx
    )
    assert not result.is_error
    # The actual request must go to the pinned IP (8.8.8.8), not the original hostname
    assert connect_urls, "no HTTP requests were made"
    assert "8.8.8.8" in connect_urls[0], (
        f"expected pinned IP in URL, got: {connect_urls[0]}"
    )
    # Host header must preserve the original hostname
    # (verified implicitly — httpx sets Host from the URL, we override with extra_headers)


@pytest.mark.asyncio
async def test_head_applies_content_type_allowlist(tmp_path) -> None:
    """web.head must enforce the content-type allowlist (parity with web.fetch)."""
    import httpx

    from liminal.handlers.web import WebConfig, WebHandler
    from liminal.protocol import Context

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/octet-stream"})

    h = WebHandler(
        default_config=WebConfig(allowed_hosts=["*"]),
        http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
        dns_resolver=lambda host: ["8.8.8.8"],
    )
    ctx = Context(identity="test", agent_name="test", credentials={}, extra={})
    result = await h.dispatch("head", {"url": "http://example.com/"}, ctx)
    assert result.is_error
    assert "content-type" in (result.error or "")


@pytest.mark.asyncio
async def test_head_caps_large_headers(tmp_path) -> None:
    """web.head must truncate oversized response header sets."""
    import httpx

    from liminal.handlers.web import WebConfig, WebHandler
    from liminal.protocol import Context

    # Generate headers totalling > 16 KB
    big_headers = {f"x-big-{i}": "x" * 200 for i in range(200)}
    big_headers["content-type"] = "text/plain"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=big_headers)

    h = WebHandler(
        default_config=WebConfig(allowed_hosts=["*"]),
        http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
        dns_resolver=lambda host: ["8.8.8.8"],
    )
    ctx = Context(identity="test", agent_name="test", credentials={}, extra={})
    result = await h.dispatch("head", {"url": "http://example.com/"}, ctx)
    assert not result.is_error
    # Should have replaced headers with the warning stub
    data = result.content[0]["data"]  # already a dict, not JSON string
    assert "x-liminal-warning" in data.get("headers", {})


# ---- SSRF deny-list regression: new ranges + v4-mapped IPv6 (#24) ----------


@pytest.mark.asyncio
async def test_rejects_v4_mapped_metadata_ipv6() -> None:
    """::ffff:169.254.169.254 is the cloud metadata IP wrapped in v4-mapped
    IPv6. It must be denied via both the ::ffff:0:0/96 range and the
    v4-normalized path (169.254.0.0/16)."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"ipv6meta.test": ["::ffff:169.254.169.254"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://ipv6meta.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


@pytest.mark.asyncio
async def test_rejects_v4_mapped_loopback_ipv6() -> None:
    """::ffff:127.0.0.1 is loopback wrapped in v4-mapped IPv6."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"ipv6loop.test": ["::ffff:127.0.0.1"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://ipv6loop.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


@pytest.mark.asyncio
async def test_rejects_cgnat_address() -> None:
    """100.64.0.0/10 (CGNAT shared space, RFC 6598) must be denied."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"cgnat.test": ["100.64.0.1"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://cgnat.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


@pytest.mark.asyncio
async def test_rejects_zero_network_address() -> None:
    """0.0.0.0 (0.0.0.0/8, 'this' network) must be denied."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"zerodot.test": ["0.0.0.0"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://zerodot.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


@pytest.mark.asyncio
async def test_rejects_nat64_wrapped_metadata() -> None:
    """A DNS64 resolver can synthesize 169.254.169.254 into the NAT64
    well-known prefix (64:ff9b::a9fe:a9fe). Not v4-mapped/6to4 — must be
    unwrapped from the low 32 bits and denied via 169.254.0.0/16."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"nat64.test": ["64:ff9b::a9fe:a9fe"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://nat64.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


@pytest.mark.asyncio
async def test_rejects_6to4_wrapped_metadata() -> None:
    """A 6to4 address (2002::/16) embeds a v4 in bytes 2-5. 2002:a9fe:a9fe::
    wraps 169.254.169.254 and must be denied via 169.254.0.0/16."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"sixtofour.test": ["2002:a9fe:a9fe::"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://sixtofour.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


async def test_rejects_ipv4_compatible_metadata() -> None:
    """Deprecated IPv4-compatible IPv6 (::a9fe:a9fe == ::169.254.169.254)
    embeds the v4 in the low 32 bits — unwrapped for symmetry and denied
    via 169.254.0.0/16."""
    handler = _build_handler(
        mock=httpx.MockTransport(lambda _: httpx.Response(200)),
        dns_map={"v4compat.test": ["::a9fe:a9fe"]},
    )
    result = await handler.dispatch(
        "fetch", {"url": "https://v4compat.test/"}, _ctx()
    )
    assert result.is_error is True
    assert "denied" in result.error or "SSRF" in result.error


# ---- pinning to the validated IP (liminal#195, #196) ----------------------


def _capturing(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    return httpx.MockTransport(handle)


@pytest.mark.asyncio
async def test_https_fetch_connects_to_the_validated_ip_with_sni() -> None:
    seen: list[httpx.Request] = []
    handler = _build_handler(
        mock=_capturing(seen), dns_map={"api.example.com": ["93.184.216.34"]}
    )
    result = await handler.dispatch("fetch", {"url": "https://api.example.com/x"}, _ctx())
    assert result.is_error is False
    (req,) = seen
    assert req.url.host == "93.184.216.34"
    assert req.headers["host"] == "api.example.com"
    assert req.extensions["sni_hostname"] == "api.example.com"


@pytest.mark.asyncio
async def test_https_head_is_pinned_too() -> None:
    seen: list[httpx.Request] = []
    handler = _build_handler(
        mock=_capturing(seen), dns_map={"api.example.com": ["93.184.216.34"]}
    )
    await handler.dispatch("head", {"url": "https://api.example.com/x"}, _ctx())
    (req,) = seen
    assert req.url.host == "93.184.216.34"
    assert req.extensions["sni_hostname"] == "api.example.com"


@pytest.mark.asyncio
async def test_ipv6_first_address_is_bracketed_not_an_invalid_url() -> None:
    seen: list[httpx.Request] = []
    v6 = "2606:2800:220:1:248:1893:25c8:1946"
    handler = _build_handler(mock=_capturing(seen), dns_map={"v6.example.com": [v6]})
    result = await handler.dispatch("fetch", {"url": "http://v6.example.com/p"}, _ctx())
    assert result.is_error is False, result.error
    (req,) = seen
    assert req.url.host == v6
    assert req.url.path == "/p"
    assert req.headers["host"] == "v6.example.com"
    assert "sni_hostname" not in req.extensions


def test_pin_request_keeps_a_non_default_port_in_url_and_host() -> None:
    url, headers, ext = _pin_request("https://api.example.com:8443/a?b=1", "93.184.216.34")
    assert url == "https://93.184.216.34:8443/a?b=1"
    assert headers == {"Host": "api.example.com:8443"}
    assert ext == {"sni_hostname": "api.example.com"}
    url, headers, _ = _pin_request("http://h.example:81/", "2001:db8::1")
    assert url == "http://[2001:db8::1]:81/"
    assert headers == {"Host": "h.example:81"}


def test_pin_request_drops_a_scheme_default_port_from_host() -> None:
    _, headers, _ = _pin_request("https://api.example.com:443/", "93.184.216.34")
    assert headers == {"Host": "api.example.com"}
    _, headers, _ = _pin_request("http://api.example.com:80/", "93.184.216.34")
    assert headers == {"Host": "api.example.com"}
    _, headers, _ = _pin_request("http://api.example.com:443/", "93.184.216.34")
    assert headers == {"Host": "api.example.com:443"}


def test_pin_request_leaves_the_url_alone_without_an_ip() -> None:
    assert _pin_request("https://api.example.com/", None) == ("https://api.example.com/", {}, {})


@pytest.mark.asyncio
async def test_pinned_https_does_not_use_the_shared_pool() -> None:
    """The pool is keyed by IP, so a pinned https request on a shared client
    could reuse a TLS session verified for another name at the same IP."""
    handler = WebHandler(default_config=WebConfig(allowed_hosts=["*"]))
    await handler.startup()
    try:
        shared, owned = handler._get_client(handler.default_config)
        assert owned is False
        isolated, owned = handler._get_client(handler.default_config, isolated=True)
        assert owned is True and isolated is not shared
        await isolated.aclose()
    finally:
        await handler.shutdown()


@pytest.mark.asyncio
async def test_clients_ignore_https_proxy_from_the_environment(monkeypatch) -> None:
    """A proxy tunnel sends the pinned IP as SNI and fails verification
    (issue #204), so neither the shared nor the per-request client may pick
    HTTPS_PROXY up from the environment."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    handler = WebHandler(default_config=WebConfig(allowed_hosts=["*"]))
    await handler.startup()
    try:
        shared, _ = handler._get_client(handler.default_config)
        isolated, _ = handler._get_client(handler.default_config, isolated=True)
        for client in (shared, isolated):
            assert client.trust_env is False
            for url in ("https://example.com/", "http://example.com/"):
                assert client._transport_for_url(httpx.URL(url)) is client._transport
        await isolated.aclose()
    finally:
        await handler.shutdown()


def test_pin_request_keeps_userinfo_so_basic_auth_still_goes() -> None:
    url, headers, _ = _pin_request("https://user:pw@hooks.example.com/x?a=1", "93.184.216.34")
    assert url == "https://user:pw@93.184.216.34/x?a=1"
    assert headers == {"Host": "hooks.example.com"}


def test_pin_request_uses_the_idna_name_for_host_and_sni() -> None:
    url, headers, ext = _pin_request("https://bücher.example/x", "93.184.216.34")
    assert url == "https://93.184.216.34/x"
    assert headers == {"Host": "xn--bcher-kva.example"}
    assert ext == {"sni_hostname": "xn--bcher-kva.example"}


@pytest.mark.asyncio
async def test_pinned_https_with_userinfo_sends_basic_auth() -> None:
    seen: list[httpx.Request] = []
    handler = _build_handler(
        mock=_capturing(seen), dns_map={"hooks.example.com": ["93.184.216.34"]}
    )
    await handler.dispatch("fetch", {"url": "https://user:pw@hooks.example.com/x"}, _ctx())
    (req,) = seen
    assert req.headers["authorization"] == "Basic dXNlcjpwdw=="
    assert req.headers["host"] == "hooks.example.com"
