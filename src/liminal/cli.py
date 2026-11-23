"""liminal CLI — `liminal version`, `liminal list-handlers`, `liminal serve`,
`liminal guide`.

`serve` runs the MCP gateway (JSON-RPC over HTTP at `POST /mcp`). `guide`
prints the guides that ship in the package; start with `liminal guide welcome`.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import Any

# Versioned declarative target config — #15.  Only version 1 is understood.
# Bump this constant (and add a migration path) before accepting a new version.
SUPPORTED_CONFIG_VERSION = 1


def _load_targets_file(path: str) -> list[Any]:
    """Parse a ``--targets`` TOML file and return validated ``TargetSpec`` list.

    Raises ``ValueError`` (with a clear message) on any config error —
    including an unsupported ``config_version`` — so the caller can print and
    exit 2 (No Silent Failures).

    Prints a ``stderr`` warning when ``config_version`` is absent, recommending
    the operator pin it explicitly.
    """
    import tomllib

    from liminal.target.config import TargetConfigError, load_target_specs

    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)

    # Reject stray top-level keys so a mistyped table-array (`[[targets]]`) or a
    # fat-fingered `config_verison` is a loud error, not a silent zero-target
    # run. Passing --targets is an explicit statement of intent (No Silent
    # Failures).
    unknown_top = set(cfg) - {"config_version", "target"}
    if unknown_top:
        raise ValueError(
            f"targets file has unknown top-level key(s): {sorted(unknown_top)}. "
            "Only `config_version` and `[[target]]` tables are allowed "
            "(did you mean `[[target]]`?)."
        )

    version = cfg.get("config_version")
    if version is None:
        print(
            "warning: targets file is missing config_version; "
            f"add `config_version = {SUPPORTED_CONFIG_VERSION}` to suppress this warning.",
            file=sys.stderr,
        )
    elif not isinstance(version, int) or isinstance(version, bool) or version != SUPPORTED_CONFIG_VERSION:
        raise ValueError(
            f"targets file config_version={version!r} is not supported "
            f"(supported: {SUPPORTED_CONFIG_VERSION}, as an integer). "
            "Upgrade liminal or use a config file generated for this version."
        )

    raw_targets = cfg.get("target", [])
    if not isinstance(raw_targets, list):
        raise ValueError(
            "targets file `target` must be an array of tables written as "
            "`[[target]]` — got a single `[target]` table. Did you mean `[[target]]`?"
        )
    if not raw_targets:
        print(
            "warning: --targets file declared no [[target]] tables (loaded 0 targets).",
            file=sys.stderr,
        )
    try:
        return load_target_specs(raw_targets)
    except TargetConfigError as exc:
        raise ValueError(f"targets file: {exc}") from exc


def _parse_trust_registry_extra(
    cfg: dict[str, Any],
) -> tuple[dict[str, Any] | None, Callable[[str], str | None] | None]:
    """Parse ``[tool_extras]`` from a trust-registry TOML dict.

    Returns ``(policy_tool_extras, None)``. The second element (the scope
    resolver) is always ``None`` now: sovereign scopes are derived from the
    handler capability cards by the server (liminal#26), not from config. A
    ``[scope_map]`` section is DEPRECATED and ignored, with a warning.

    ``policy_tool_extras`` is ``None`` when ``[tool_extras]`` is absent.

    Raises ``ValueError`` with a clear diagnostic on a malformed
    ``[tool_extras]`` so ``cli.main()`` can print and exit 2 without silently
    passing bad config (CLAUDE.md: No Silent Failures).

    ``[tool_extras]`` is a flat table passed verbatim as ``policy_tool_extras``::

        [tool_extras]
        "memory.db_path" = "/shared/memory.db"
    """
    # [tool_extras] — flat TOML table → passed verbatim
    tool_extras_raw = cfg.get("tool_extras")
    if tool_extras_raw is not None and not isinstance(tool_extras_raw, dict):
        raise ValueError(
            f"[tool_extras] in the trust registry must be a TOML table (dict); "
            f"got {type(tool_extras_raw).__name__!r}. "
            "Check the registry file for a malformed [tool_extras] section."
        )
    policy_tool_extras: dict[str, Any] | None = tool_extras_raw

    # [scope_map] is DEPRECATED (liminal#26): sovereign scopes are now derived
    # from each handler's CapabilityCard.required_scope, so the vocabulary can't
    # drift from the handler surface. A present [scope_map] is ignored (with a
    # warning) rather than silently honoured.
    if cfg.get("scope_map") is not None:
        print(
            "warning: [scope_map] is deprecated and ignored — sovereign scopes "
            "are now derived from handler capability cards (required_scope). "
            "Remove [scope_map] from the trust registry.",
            file=sys.stderr,
        )

    return policy_tool_extras, None


_ALLOW_NONLOOPBACK_ENV = "LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK"


def _is_loopback_host(host: str) -> bool:
    """True only for 127.0.0.0/8, ::1 and `localhost`. Anything else (0.0.0.0, ::,
    a LAN IP, any other hostname, a value that does not parse) is not loopback:
    the check fails closed."""
    import ipaddress

    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback


def _check_auth_off_bind(host: str, auth_disabled: bool) -> str | None:
    """Gate for `serve` (liminal#214): auth off plus a non-loopback bind hands
    every tool to anyone who can reach the port. Returns an error message to
    exit 2 with, or None to proceed. LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK=1
    overrides, with a warning, for a container whose port is published to
    loopback only."""
    if not auth_disabled or _is_loopback_host(host):
        return None
    if (os.environ.get(_ALLOW_NONLOOPBACK_ENV, "").lower()) in {"1", "true", "yes", "on"}:
        print(
            f"warning: LIMINAL_AUTH_DISABLED=1 with --host {host} (not loopback), "
            f"allowed by {_ALLOW_NONLOOPBACK_ENV}=1. Anyone who can reach this port "
            "has every tool, with no authentication. The port must be published to "
            "loopback only (e.g. docker -p 127.0.0.1:9100:9100).",
            file=sys.stderr,
        )
        return None
    return (
        f"LIMINAL_AUTH_DISABLED=1 with --host {host} (not loopback): anyone who can "
        "reach the port would get every tool with no authentication. Bind "
        "127.0.0.1, configure --jwks-url or --trust-registry, or, for a container "
        f"whose port is published to loopback only, set {_ALLOW_NONLOOPBACK_ENV}=1."
    )


def _env(name: str, fallback: str | None = None) -> str | None:
    """A `serve` flag's default from the environment: a container image bakes
    its CMD once, so where a deployment cannot change argv (a platform that
    renders the Deployment, 2026-10-04) the same knobs arrive as
    LIMINAL_* env. The flag on the command line still wins."""
    value = os.environ.get(name, "")
    return value if value else fallback


def _guide(name: str | None) -> int:
    """Print one bundled guide as raw markdown, or list them. An agent is the
    expected reader, so the output is meant to be read into context as is."""
    from liminal.docs import GUIDES, bundled_guide

    if not name:
        print("Bundled guides (`liminal guide <name>`):\n")
        for n, line in GUIDES.items():
            print(f"  {n:<12}  {line}")
        return 0
    try:
        print(bundled_guide(name), end="")
    except KeyError:
        print(
            f"error: no bundled guide named {name!r}. Valid: {', '.join(GUIDES)}",
            file=sys.stderr,
        )
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="liminal", description=__doc__)
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("version", help="Print the liminal version")
    list_p = sub.add_parser("list-handlers", help="Discover + print registered handlers")
    list_p.add_argument(
        "--cards", action="store_true", help="Also print each handler's capability card"
    )

    guide_p = sub.add_parser(
        "guide", help="List the bundled guides, or print one (start with `welcome`)"
    )
    guide_p.add_argument("name", nargs="?", help="Guide to print; omit to list them")

    serve_p = sub.add_parser("serve", help="Run the MCP HTTP server")
    serve_p.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Bind address (default 127.0.0.1). 0.0.0.0 listens on every interface. "
            "With LIMINAL_AUTH_DISABLED=1 a non-loopback host is refused (exit 2) "
            "unless LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK=1."
        ),
    )
    serve_p.add_argument("--port", type=int, default=9100, help="Bind port (default 9100).")
    serve_p.add_argument(
        "--jwks-url",
        default=_env("LIMINAL_JWKS_URL"),
        help=(
            "URL of the JWKS to verify caller tokens against (single-cabal "
            "mode). Some verifier is required for tools/list and tools/call: "
            "this, or --trust-registry (sovereign mode), unless "
            "LIMINAL_AUTH_DISABLED=1."
        ),
    )
    serve_p.add_argument(
        "--issuer",
        default=_env("LIMINAL_ISSUER", "cabal-core"),
        help="Expected `iss` claim (single-issuer mode).",
    )
    serve_p.add_argument(
        "--audience",
        default=_env("LIMINAL_AUDIENCE", "liminal"),
        help=(
            "Expected `aud` claim (single-issuer mode). Tokens minted for a "
            "different audience are rejected; this knob is what lets a "
            "deployment demand a liminal-specific audience instead of the "
            "hardcoded default. Sovereign mode takes its audience from the "
            "trust registry's `service_audience` instead."
        ),
    )
    serve_p.add_argument(
        "--trust-registry",
        default=None,
        help=(
            "Path to a multi-issuer trust registry TOML (SOVEREIGN mode — a "
            "graduated singleton persona serving several cabals). Mutually "
            "exclusive with --jwks-url; requires --policy-db. TOML shape: a "
            "top-level `service_audience` string + [[issuer]] tables with "
            "id/jwks_uri/parent. Exactly one issuer sets parent = true, and "
            "that issuer must also name `admin_personas` (a list of persona "
            "names; serve exits 2 without it). An optional [tool_extras] "
            "table is passed verbatim to the policy layer."
        ),
    )
    serve_p.add_argument(
        "--policy-db",
        default=None,
        help=(
            "Path to the SQLite policy store backing sovereign authorization. "
            "Required with --trust-registry; nonsensical without it."
        ),
    )
    serve_p.add_argument(
        "--admin-port",
        type=int,
        default=None,
        help=(
            "Serve the federation admin surface (/admin/*) on its OWN "
            "listener at this port, and keep it entirely off the data-plane "
            "port -- so a network policy can restrict admin to the governing "
            "service alone. Requires --trust-registry. Unset: admin rides "
            "the data-plane port (with a loud warning)."
        ),
    )
    serve_p.add_argument(
        "--admin-host",
        default="127.0.0.1",
        help="Bind host for --admin-port (default 127.0.0.1).",
    )
    serve_p.add_argument(
        "--cabal-url",
        default=_env("LIMINAL_CABAL_URL"),
        help=(
            "Base URL of Cabal Core (e.g. http://cabal-core:7400). When "
            "combined with --cabal-token-env, wires CabalCoreCredentialResolver "
            "so credentialed handlers (slack, github, etc.) get their secrets "
            "fetched from Cabal at dispatch time."
        ),
    )
    serve_p.add_argument(
        "--cabal-token-env",
        default="LIMINAL_CABAL_TOKEN",
        help=(
            "Name of the env var holding a long-lived JWT with scope=secrets-fetch "
            "that liminal presents to Cabal Core. Generate one with "
            "`cbl token mint-service --scope secrets-fetch`. Default: LIMINAL_CABAL_TOKEN."
        ),
    )
    serve_p.add_argument(
        "--cred-cache-ttl",
        type=float,
        default=15 * 60,
        help=(
            "TTL in seconds for cached non-empty credential answers "
            "(default 900; empty answers are not cached)."
        ),
    )
    serve_p.add_argument(
        "--revocation-ttl",
        type=float,
        default=30.0,
        help=(
            "Seconds between fetches of cabal's revocation list "
            "(GET <cabal-url>/auth/revocations, default 30). Tokens from the "
            "cabal at --cabal-url whose subject it revoked are refused within "
            "this window. Needs --cabal-url."
        ),
    )
    serve_p.add_argument(
        "--targets",
        default=_env("LIMINAL_TARGETS"),
        metavar="PATH",
        help=(
            "Path to a versioned targets TOML file declaring federated MCP upstreams "
            "(``[[target]]`` tables). The file should set ``config_version = 1``; "
            "a file without it loads with a warning. "
            "Works in both --jwks-url (single-cabal) and --trust-registry (sovereign) modes. "
            "Example: ``liminal serve --jwks-url ... --targets targets.toml``."
        ),
    )

    args = parser.parse_args(argv)

    if args.cmd == "version" or args.cmd is None:
        from liminal import __version__

        print(f"liminal {__version__}")
        return 0

    if args.cmd == "guide":
        return _guide(args.name)

    if args.cmd == "list-handlers":
        from liminal.registry import discover_handlers

        registry = discover_handlers()
        if not len(registry):
            print("(no handlers registered)", file=sys.stderr)
            return 0
        for record in registry:
            print(f"{record.name:<20}  {record.card.description}")
            if args.cards:
                print(f"  source: {record.source}")
                print(f"  tools:  {[t.name for t in record.card.tools]}")
                print(f"  creds:  {record.card.credential_keys or '(none)'}")
                print(f"  labels: {record.card.labels or '{}'}")
                print()
        return 0

    if args.cmd == "serve":
        import os

        import uvicorn

        from liminal.server import (
            CabalCoreCredentialResolver,
            ConfigError,
            IssuerConfig,
            JWTVerifier,
            ParentNarrowingConflict,
            SqlitePolicyStore,
            URLJWKSVerifier,
            build_multi_issuer_verifier,
            create_app,
        )
        from liminal.server.app import _auth_disabled_from_env

        bind_error = _check_auth_off_bind(args.host, _auth_disabled_from_env())
        if bind_error:
            print(f"error: {bind_error}", file=sys.stderr)
            return 2

        # Config guards: single-issuer (--jwks-url) XOR sovereign
        # (--trust-registry + --policy-db).
        if args.jwks_url and args.trust_registry:
            print(
                "error: --jwks-url and --trust-registry are mutually exclusive "
                "(single-cabal vs sovereign mode).",
                file=sys.stderr,
            )
            return 2
        if args.policy_db and not args.trust_registry:
            print(
                "error: --policy-db requires --trust-registry (server-side authz "
                "is only meaningful with a multi-issuer verifier).",
                file=sys.stderr,
            )
            return 2

        verifier: JWTVerifier | None = None
        policy_store = None
        policy_tool_extras: dict[str, Any] | None = None
        policy_scope_for: Callable[[str], str | None] | None = None
        # Discover the handler registry ONCE and reuse it for both the derived
        # scope-map banner and create_app, so the banner can't drift from what
        # the app enforces if the serve path ever gains per-persona filtering
        # (Prudence #41 review).
        from liminal.registry import discover_handlers

        # Handler factories read their config from the environment. The cabal
        # handler sends A2A calls to the same cabal --cabal-url names, so a
        # flag given without the variable still reaches it (liminal#189).
        if args.cabal_url and not os.environ.get("LIMINAL_CABAL_URL"):
            os.environ["LIMINAL_CABAL_URL"] = args.cabal_url
        reg = discover_handlers()

        def _revocations_for(issuer: str):
            # liminal#228: refuse tokens whose subject the cabal at --cabal-url
            # revoked. Only that cabal's own issuer is checked, with the same
            # bearer the credential resolver presents. Fetched on demand, so
            # under LIMINAL_AUTH_DISABLED=1 (no verifier) nothing is fetched.
            if not args.cabal_url:
                return None
            from liminal.server.revocations import RevocationList

            print(
                f"revocations: checking issuer {issuer!r} against "
                f"{args.cabal_url.rstrip('/')}/auth/revocations "
                f"(refresh {args.revocation_ttl}s)",
                file=sys.stderr,
            )
            return RevocationList(
                cabal_url=args.cabal_url,
                issuer=issuer,
                token_provider=lambda _env_name=args.cabal_token_env: os.environ.get(
                    _env_name, ""
                ),
                ttl_seconds=args.revocation_ttl,
            )

        if args.trust_registry:
            import tomllib

            if not args.policy_db:
                print(
                    "error: --trust-registry requires --policy-db (sovereign mode "
                    "must have server-side authorization).",
                    file=sys.stderr,
                )
                return 2
            with open(args.trust_registry, "rb") as fh:
                cfg = tomllib.load(fh)
            service_audience = cfg.get("service_audience")
            if not service_audience:
                print(
                    "error: trust registry is missing a top-level `service_audience`.",
                    file=sys.stderr,
                )
                return 2
            issuers = [
                IssuerConfig(
                    id=i["id"], jwks_uri=i["jwks_uri"], parent=bool(i.get("parent", False)),
                    exchange_uri=i.get("exchange_uri"),
                )
                for i in cfg.get("issuer", [])
            ]
            try:
                policy_tool_extras, policy_scope_for = _parse_trust_registry_extra(cfg)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            # --cabal-url is the parent's cabal: the credential resolver is only
            # called for the parent's callers (liminal#143), so its revocation
            # list applies to the parent issuer's tokens and no other's.
            _parents = [i.id for i in issuers if i.parent]
            try:
                verifier = build_multi_issuer_verifier(
                    issuers,
                    service_audience=service_audience,
                    revocations=(
                        _revocations_for(_parents[0]) if len(_parents) == 1 else None
                    ),
                )
            except ValueError as exc:
                # No parent, several parents, no issuers, or duplicate ids:
                # a registry mistake, so exit 2 with a diagnostic rather than
                # a traceback (liminal#144). This also guards the next() below,
                # which assumes exactly one parent.
                print(f"error: trust registry {args.trust_registry}: {exc}", file=sys.stderr)
                return 2
            parent_issuer = next(i.id for i in issuers if i.parent)
            # Admin standing is per-persona (liminal#73): the parent's
            # [[issuer]] table may name `admin_personas`; each named persona
            # gets its own immutable parent row, and ONLY those personas pass
            # the guardian gate. Absent, the CLI refuses to serve -- see the
            # guard below for why the issuer count is not the axis.
            #
            # This comment previously described the GRADUATED behaviour
            # (refuse at one issuer, warn otherwise) that round 1 identified as
            # Critical 2 and this branch removed. It was left standing eight
            # lines above a comment that said the opposite, and the stale one
            # is what a reader meets first -- so a maintainer reading top-down
            # would have learned the removed rule as the design, which is the
            # path back to reintroducing it. (Prudence, liminal#83 round 2.)
            parent_cfg = next(
                i for i in cfg.get("issuer", []) if i.get("parent", False)
            )
            admin_personas = tuple(parent_cfg.get("admin_personas", ()) or ())
            # THE HAZARD'S AXIS IS NOT THE ISSUER COUNT (liminal#83 round 1).
            # This previously refused only when len(issuers) == 1 and warned
            # otherwise -- so adding an UNRELATED second issuer downgraded the
            # refusal to a warning while reducing the parent's own agents'
            # exposure not at all. Driven by the reviewer against the real CLI:
            # an ungranted agent got 200 on /admin/policy, self-granted admin:*,
            # dispatched, and revoked the partner cabal.
            #
            # Every issuer in the registry is a DATA-PLANE issuer -- its tokens
            # are accepted on /mcp -- so the parent always signs data-plane
            # tokens, and without admin_personas every persona it mints holds
            # admin standing. That is true at one issuer and at ten.
            #
            # This does NOT reintroduce the hard parent != issuer refusal that
            # #73 asked for and this PR rightly declined: the designed
            # federation, where the parent is legitimately a trusted data-plane
            # issuer, is served by naming admin_personas and is not refused.
            # The PR's own `home` fixture is that case.
            if not admin_personas:
                print(
                    f"error: parent issuer {parent_issuer!r} names no "
                    "`admin_personas` -- EVERY persona it mints would hold "
                    "admin:* on /admin/*, so every data-plane token doubles as "
                    "an admin token. This is independent of how many other "
                    "issuers the registry trusts. Name the persona(s) allowed "
                    "to administer policy, e.g. "
                    "admin_personas = [\"room-operator\"].",
                    file=sys.stderr,
                )
                return 2
            if "*" in admin_personas:
                # `["*"]` is TRUTHY, so it passes the guard above and then seeds
                # the historical wildcard row -- reaching exactly the state that
                # error describes as unacceptable, with LESS signal than before
                # this branch, since the old graduated code warned in this same
                # topology and that warning was removed with it.
                #
                # Not forbidden: admin.py calls a wildcard parent row "an
                # explicit deployment choice, not a fallback", and it is. But it
                # is the choice an operator is most likely to make TO SILENCE
                # THE ERROR ABOVE when they have no persona name to hand, so it
                # must not be silent. (Prudence, liminal#83 round 2, Important 1
                # -- the same "control and compensating signal fail together"
                # shape this branch fixed for Critical 1.)
                print(
                    f"warning: parent issuer {parent_issuer!r} names "
                    "admin_personas = [\"*\"] -- EVERY persona it mints holds "
                    "admin:* on /admin/*, which is the state the missing-"
                    "admin_personas error refuses. This is an explicit "
                    "deployment choice and is permitted.\n"
                    "  To narrow it you need a NEW --policy-db as well: this "
                    "boot seeds the wildcard parent row, and naming specific "
                    "personas against the same database is then refused as a "
                    "narrowing (the row is immutable, so the narrowing would "
                    "be a no-op).",
                    file=sys.stderr,
                )
            try:
                policy_store = SqlitePolicyStore(
                    args.policy_db,
                    parent_issuer=parent_issuer,
                    parent_personas=admin_personas or ("*",),
                )
            except ParentNarrowingConflict as exc:
                # A no-op narrowing must not serve. The trigger is ANY removal
                # from the set of personas already seeded — wildcard or named —
                # because seeding is idempotent per (issuer, persona) while rows
                # are immutable, so a dropped persona keeps answering. Widening
                # to "*" is exempt: nothing can lose standing under a wildcard.
                # ParentIssuerDemoted (a subclass) lands here too: the store
                # holds parent rows for an issuer the registry no longer names
                # as parent (liminal#87).
                print(f"error: {exc}", file=sys.stderr)
                return 2
            # Print the derived handler->scope map so an operator can reconcile
            # grants on upgrade (scope enforcement is now real — a non-admin
            # grant must hold each listed scope, or admin:*). See liminal#26.
            _derived = {
                r.name: r.card.required_scope
                for r in reg
                if r.card.required_scope
            }
            if _derived:
                _map = ", ".join(f"{h}->{s}" for h, s in sorted(_derived.items()))
                print(
                    f"sovereign scope enforcement (handler-derived): {_map}. "
                    "Non-admin grants must hold these scopes (or admin:*).",
                    file=sys.stderr,
                )
            else:
                print(
                    "sovereign scope enforcement: handler-derived "
                    "(no handler declares a required_scope)",
                    file=sys.stderr,
                )
            if policy_tool_extras is not None:
                print(
                    f"sovereign tool extras: {len(policy_tool_extras)} key(s) wired "
                    "from [tool_extras]",
                    file=sys.stderr,
                )
            print(
                f"sovereign mode: {len(issuers)} trusted issuer(s), parent "
                f"{parent_issuer!r}, audience {service_audience!r}, policy db "
                f"{args.policy_db}",
                file=sys.stderr,
            )
        elif args.jwks_url:
            verifier = URLJWKSVerifier(
                jwks_url=args.jwks_url,
                expected_issuer=args.issuer,
                expected_audience=args.audience,
                revocations=_revocations_for(args.issuer),
            )
        elif not _auth_disabled_from_env():
            # Under LIMINAL_AUTH_DISABLED=1 no verifier is the required setup
            # (create_app refuses both together) and requests are accepted with
            # synthesised claims, so the warning would be false there.
            print(
                "warning: no verifier configured (--jwks-url or --trust-registry); "
                "tools/list and tools/call will reject every request",
                file=sys.stderr,
            )

        credential_resolver = None
        if args.cabal_url:
            token = os.environ.get(args.cabal_token_env)
            if not token:
                print(
                    f"warning: --cabal-url set but ${args.cabal_token_env} is empty; "
                    "credential fetches will fail (handlers needing secrets will see empty creds).",
                    file=sys.stderr,
                )

            def _token_provider(
                _env_name=args.cabal_token_env,
            ) -> str:
                # Re-read every call so a rotation (operator restarts an
                # external secrets manager) propagates without a daemon
                # restart.
                return os.environ.get(_env_name, "")

            resolver = CabalCoreCredentialResolver(
                cabal_url=args.cabal_url,
                token_provider=_token_provider,
                cache_ttl_seconds=args.cred_cache_ttl,
            )
            credential_resolver = resolver.fetch
            print(
                f"credentials: resolver wired against {args.cabal_url} "
                f"(token env: {args.cabal_token_env}, ttl: {args.cred_cache_ttl}s)",
                file=sys.stderr,
            )

        # Load declarative federated targets if --targets was supplied (#15).
        # Not auth-mode-specific: works with --jwks-url and --trust-registry alike.
        targets = None
        if args.targets:
            try:
                targets = _load_targets_file(args.targets)
            except (ValueError, OSError) as exc:
                print(f"error: --targets: {exc}", file=sys.stderr)
                return 2
            print(
                f"targets: loaded {len(targets)} target(s) from {args.targets}",
                file=sys.stderr,
            )

        # create_app runs targets through build_http_targets, which raises
        # TargetConfigError for a name that collides with an in-process handler
        # or a stdio target (not served until Stage B). Catch it on the same
        # `--targets` exit-2 path so it's a clean diagnostic, not a traceback.
        from liminal.target.config import TargetConfigError

        if args.admin_port is not None and policy_store is None:
            print(
                "error: --admin-port requires --trust-registry (there is no "
                "admin surface without a policy store).",
                file=sys.stderr,
            )
            return 2
        if policy_store is not None and args.admin_port is None:
            print(
                "warning: the federation admin surface (/admin/*) is riding "
                "the data-plane port. Give it its own listener with "
                "--admin-port so the network layer can restrict who reaches "
                "it.",
                file=sys.stderr,
            )

        # Live targets (liminal#222): with a policy DB, the admin plane can add,
        # replace and remove federated targets while serving; they persist in
        # that database and come back at boot. The targets file stays the seed.
        live_targets = None
        if policy_store is not None:
            from liminal.server.live_targets import LiveTargets, LiveTargetStore

            live_targets = LiveTargets(LiveTargetStore(args.policy_db))
            print(
                "targets: live targets enabled (PUT/DELETE /admin/targets/<name>, "
                f"stored in {args.policy_db})",
                file=sys.stderr,
            )

        try:
            app = create_app(
                jwt_verifier=verifier,
                registry=reg,
                credential_resolver=credential_resolver,
                policy_store=policy_store,
                policy_scope_for=policy_scope_for,
                policy_tool_extras=policy_tool_extras,
                targets=targets,
                mount_admin=args.admin_port is None,
                live_targets=live_targets,
            )
        except TargetConfigError as exc:
            print(f"error: --targets: {exc}", file=sys.stderr)
            return 2
        except ConfigError as exc:
            # Build-time operator-config guards in create_app (e.g. AUTH_DISABLED
            # alongside a verifier) — a clean exit-2 diagnostic, not a traceback
            # (liminal#31).
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.admin_port is not None:
            # Two listeners, one process (liminal#74): the data plane binds
            # --host/--port with no /admin/* routes at all; the admin surface
            # binds --admin-host/--admin-port so deployments can fence it off
            # at the network layer.
            import asyncio

            from liminal.server import create_admin_app

            admin_app = create_admin_app(
                jwt_verifier=verifier,
                policy_store=policy_store,
                live_targets=live_targets,
                registry=reg,
            )
            print(
                f"admin surface: own listener on "
                f"{args.admin_host}:{args.admin_port} (data plane carries no "
                "/admin/* routes)",
                file=sys.stderr,
            )

            async def _serve_both() -> None:
                data_plane = uvicorn.Server(
                    uvicorn.Config(
                        app, host=args.host, port=args.port, log_level="info"
                    )
                )
                admin_plane = uvicorn.Server(
                    uvicorn.Config(
                        admin_app,
                        host=args.admin_host,
                        port=args.admin_port,
                        log_level="info",
                    )
                )
                await asyncio.gather(data_plane.serve(), admin_plane.serve())

            asyncio.run(_serve_both())
            return 0

        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
