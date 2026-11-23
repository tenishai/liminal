"""Shared outbound-address policy for handlers that make HTTP requests.

`web` and `notify` both resolve a caller-supplied hostname and must refuse it
when any resolved address lands in an internal range. They share this one
implementation so the two checks cannot drift apart (notify once checked only
the raw address and missed IPv4 embedded in IPv6 forms that web unwrapped).

Not a handler: discovery reads the `liminal.handlers` entry points only.
"""

from __future__ import annotations

import ipaddress
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Default network denies. Operators can extend but should not weaken.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS / Azure / GCP metadata
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT shared space (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),       # "This" network (RFC 1122 §3.2.1.3)
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # limited broadcast (within 240/4; explicit for clarity)
    ipaddress.ip_network("::/128"),          # unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # ULA
    ipaddress.ip_network("fe80::/10"),       # link-local
    ipaddress.ip_network("::ffff:0:0/96"),   # v4-mapped IPv6 (belt-and-suspenders)
]

_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
_V4_COMPATIBLE = ipaddress.ip_network("::/96")


def embedded_v4s(ip: IPAddress) -> list[ipaddress.IPv4Address]:
    """Extract any IPv4 address embedded in an IPv6 address.

    An IPv6 address can wrap a v4 target that a gateway translates back to
    IPv4 at connect time — so the embedded v4 must also be checked against
    the IPv4 deny ranges, or a metadata/loopback IP slips past wearing an
    IPv6 disguise. Four transition mechanisms embed a v4:

      - v4-mapped (::ffff:a.b.c.d) — already blanket-denied by the
        ::ffff:0:0/96 range in PRIVATE_NETWORKS; unwrapped here belt-and-
        suspenders so the check stays correct if someone ever narrows that
        range.
      - 6to4 (2002::/16) — bytes 2-5 carry the v4 (ip.sixtofour).
      - NAT64 (64:ff9b::/96 well-known prefix) — the low 32 bits carry the
        v4; a DNS64 resolver synthesizes e.g. 64:ff9b::a9fe:a9fe for
        169.254.169.254, which is neither v4-mapped nor 6to4.
      - IPv4-compatible (::a.b.c.d, the ::/96 low-32-bits form) — deprecated
        by RFC 4291 §2.5.5.1 and not routed/translated by modern stacks, but
        unwrapped for symmetry so every low-32-bits embedding is covered.

    Deliberately out of scope: RFC 6052 network-specific NAT64 prefixes and
    the RFC 8215 64:ff9b:1::/48 local-use prefix — below /96 the v4 is not in
    a contiguous low-32-bits slot, so they can't be handled generically; only
    the 64:ff9b::/96 well-known prefix is unwrapped.
    """
    out: list[ipaddress.IPv4Address] = []
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            out.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            out.append(ip.sixtofour)
        if ip in _NAT64_WKP:
            out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip in _V4_COMPATIBLE:
            out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def denied_network(ip: IPAddress, denied_networks: list[Any]) -> Any | None:
    """Return the first deny range that `ip`, or any IPv4 embedded in it,
    falls in; None when the address is allowed."""
    for check_ip in (ip, *embedded_v4s(ip)):
        for net in denied_networks:
            if check_ip in net:
                return net
    return None
