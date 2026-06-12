"""Factory for picking a LimenalClient impl from config.

The deployment chooses between library and proxy mode via one config
flag; callers code against the LimenalClient Protocol and don't care
which impl is wired in.
"""

from __future__ import annotations

from typing import Any

from limenal.client.library import LibraryLimenalClient
from limenal.client.protocol import LimenalClient
from limenal.client.proxy import ProxyLimenalClient

__all__ = ["from_config"]


def from_config(config: dict[str, Any]) -> LimenalClient:
    """Build a LimenalClient from a config dict.

    Expected shapes:
        {"mode": "library", "registry": Registry,
         "default_identity": "...", "default_agent_name": "...",
         "credential_resolver": ...}

        {"mode": "proxy", "url": "http://limenal:9100",
         "token_provider": Callable[[], str], "http_client": ...}

    Anything beyond `mode` is forwarded to the chosen impl's constructor.
    """
    mode = config.get("mode")
    if mode == "library":
        kwargs = {k: v for k, v in config.items() if k != "mode"}
        return LibraryLimenalClient(**kwargs)
    if mode == "proxy":
        kwargs = {k: v for k, v in config.items() if k not in ("mode", "url")}
        url = config.get("url")
        if not url:
            raise ValueError("proxy mode requires 'url' in config")
        return ProxyLimenalClient(base_url=url, **kwargs)
    raise ValueError(
        f"unknown LimenalClient mode {mode!r}; expected 'library' or 'proxy'"
    )
