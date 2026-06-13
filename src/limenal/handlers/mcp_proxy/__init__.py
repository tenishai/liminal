"""Generic MCP proxy handler — forward tool calls to upstream MCP servers.

This is the headline limenal feature for plugin extensibility. The same
handler shape does three jobs:

  1. Persona graduation: when a cabal persona externalizes from an
     in-process handler to a standalone container, the cabal-side
     limenal entry becomes an mcp_proxy entry pointing at the
     container's URL. Zero code change on either side.
  2. Third-party MCP server integration: Atlassian Jira, Slack,
     GitHub, Anthropic's filesystem MCP — each becomes one config
     stanza. Limenal's tool list grows to include the upstream's
     tools, namespaced by the configured prefix.
  3. Limenal-as-standalone-MCP-gateway: operators with no Cabal can
     run limenal as a unified aggregator pointed at their existing
     MCP-server fleet.

The proxy is configured via Python objects (ProxyConfig list passed
to create_app), not entry-points — each upstream becomes its own
handler entry in limenal's runtime registry under its `prefix` name.
Limenal's existing dispatch path prepends the handler name to the
tool, so a "jira" proxy with upstream tool "search" automatically
appears in the agent's tool list as "jira.search".
"""

from limenal.handlers.mcp_proxy.config import ProxyConfig
from limenal.handlers.mcp_proxy.handler import MCPProxyHandler
from limenal.handlers.mcp_proxy.register import (
    ProxyRegistrationError,
    register_proxies,
)

__all__ = [
    "MCPProxyHandler",
    "ProxyConfig",
    "ProxyRegistrationError",
    "register_proxies",
]
