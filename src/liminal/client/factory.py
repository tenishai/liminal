"""Factory for picking a LiminalClient impl from config.

The deployment chooses between library and proxy mode via one config
flag; callers code against the LiminalClient Protocol and don't care
which impl is wired in.
"""

from __future__ import annotations

from typing import Any

from liminal.client.library import LibraryLiminalClient
from liminal.client.protocol import LiminalClient
from liminal.client.proxy import ProxyLiminalClient

__all__ = ["from_config"]


def from_config(config: dict[str, Any]) -> LiminalClient:
    """Build a LiminalClient from a config dict.

    Expected shapes:
        {"mode": "library", "registry": Registry,
         "default_identity": "...", "default_agent_name": "...",
         "credential_resolver": ...}

        {"mode": "proxy", "url": "http://liminal:9100",
         "token_provider": Callable[[], str], "http_client": ...}

    Anything beyond `mode` is forwarded to the chosen impl's constructor.
    """
    mode = config.get("mode")
    if mode == "library":
        kwargs = {k: v for k, v in config.items() if k != "mode"}
        return LibraryLiminalClient(**kwargs)
    if mode == "proxy":
        kwargs = {k: v for k, v in config.items() if k not in ("mode", "url")}
        url = config.get("url")
        if not url:
            raise ValueError("proxy mode requires 'url' in config")
        return ProxyLiminalClient(base_url=url, **kwargs)
    raise ValueError(
        f"unknown LiminalClient mode {mode!r}; expected 'library' or 'proxy'"
    )
