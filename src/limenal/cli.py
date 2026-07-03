"""Tiny CLI — `limenal --version`, `limenal list-handlers`.

The real serve mode comes in Phase 1.5 when the MCP HTTP/SSE server
lands.
"""

from __future__ import annotations

import argparse
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

    from limenal.target.config import TargetConfigError, load_target_specs

    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)

    version = cfg.get("config_version")
    if version is None:
        print(
            "warning: targets file is missing config_version; "
            f"add `config_version = {SUPPORTED_CONFIG_VERSION}` to suppress this warning.",
            file=sys.stderr,
        )
    elif version != SUPPORTED_CONFIG_VERSION:
        raise ValueError(
            f"targets file config_version={version!r} is not supported "
            f"(supported: {SUPPORTED_CONFIG_VERSION}). "
            "Upgrade limenal or use a config file generated for this version."
        )

    raw_targets = cfg.get("target", [])
    try:
        return load_target_specs(raw_targets)
    except TargetConfigError as exc:
        raise ValueError(f"targets file: {exc}") from exc


def _parse_trust_registry_extra(
    cfg: dict[str, Any],
) -> tuple[dict[str, Any] | None, Callable[[str], str | None] | None]:
    """Parse ``[tool_extras]`` and ``[scope_map]`` from a trust-registry TOML dict.

    Returns ``(policy_tool_extras, policy_scope_for)``.  Both are ``None``
    when the corresponding TOML section is absent — preserving the exact
    current behaviour (no scope enforcement, no server-set tool extras).

    Raises ``ValueError`` with a clear diagnostic on any malformed input so
    ``cli.main()`` can print and exit 2 without silently passing bad config
    (CLAUDE.md: No Silent Failures).

    ``[tool_extras]`` is a flat table passed verbatim as ``policy_tool_extras``::

        [tool_extras]
        "memory.db_path" = "/shared/memory.db"

    ``[scope_map]`` maps handler names to the scope string that handler
    requires; absent handlers get ``None`` (no scope requirement)::

        [scope_map]
        scratchpad = "mem:append"
        memory = "mem:query"
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

    # [scope_map] — table of handler-name → required-scope (string values only)
    scope_map_raw = cfg.get("scope_map")
    policy_scope_for: Callable[[str], str | None] | None = None
    if scope_map_raw is not None:
        if not isinstance(scope_map_raw, dict):
            raise ValueError(
                f"[scope_map] in the trust registry must be a TOML table (dict); "
                f"got {type(scope_map_raw).__name__!r}. "
                "Check the registry file for a malformed [scope_map] section."
            )
        for handler_key, scope_val in scope_map_raw.items():
            if not isinstance(scope_val, str):
                raise ValueError(
                    f"[scope_map] values must be strings; "
                    f"key {handler_key!r} has a {type(scope_val).__name__!r} value. "
                    "Each handler should map to a single scope string, e.g. "
                    f'{handler_key!r} = "mem:query".'
                )
        scope_map: dict[str, str] = dict(scope_map_raw)

        def _scope_for(handler: str, _sm: dict[str, str] = scope_map) -> str | None:
            return _sm.get(handler)

        policy_scope_for = _scope_for

    return policy_tool_extras, policy_scope_for


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="limenal", description=__doc__)
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("version", help="Print the limenal version")
    list_p = sub.add_parser("list-handlers", help="Discover + print registered handlers")
    list_p.add_argument(
        "--cards", action="store_true", help="Also print each handler's capability card"
    )

    serve_p = sub.add_parser("serve", help="Run the MCP HTTP server")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=9100)
    serve_p.add_argument(
        "--jwks-url",
        default=None,
        help="URL of the JWKS to verify caller tokens against. Required for any authenticated method (tools/list, tools/call).",
    )
    serve_p.add_argument(
        "--issuer", default="cabal-core", help="Expected `iss` claim (single-issuer mode)."
    )
    serve_p.add_argument(
        "--trust-registry",
        default=None,
        help=(
            "Path to a multi-issuer trust registry TOML (SOVEREIGN mode — a "
            "graduated singleton persona serving several cabals). Mutually "
            "exclusive with --jwks-url; requires --policy-db. TOML shape: a "
            "top-level `service_audience` string + [[issuer]] tables with "
            "id/jwks_uri/parent."
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
        "--cabal-url",
        default=None,
        help=(
            "Base URL of Cabal Core (e.g. http://cabal-core:7400). When "
            "combined with --cabal-token-env, wires CabalCoreCredentialResolver "
            "so credentialed handlers (slack, github, etc.) get their secrets "
            "fetched from Cabal at dispatch time."
        ),
    )
    serve_p.add_argument(
        "--cabal-token-env",
        default="LIMENAL_CABAL_TOKEN",
        help=(
            "Name of the env var holding a long-lived JWT with scope=secrets-fetch "
            "that limenal presents to Cabal Core. Generate one with "
            "`cbl token mint-service --scope secrets-fetch`. Default: LIMENAL_CABAL_TOKEN."
        ),
    )
    serve_p.add_argument(
        "--cred-cache-ttl",
        type=float,
        default=15 * 60,
        help="Credential cache TTL in seconds (default 900).",
    )
    serve_p.add_argument(
        "--targets",
        default=None,
        metavar="PATH",
        help=(
            "Path to a versioned targets TOML file declaring federated MCP upstreams "
            "(``[[target]]`` tables). The file must set ``config_version = 1``. "
            "Works in both --jwks-url (single-cabal) and --trust-registry (sovereign) modes. "
            "Example: ``limenal serve --jwks-url ... --targets targets.toml``."
        ),
    )

    args = parser.parse_args(argv)

    if args.cmd == "version" or args.cmd is None:
        from limenal import __version__

        print(f"limenal {__version__}")
        return 0

    if args.cmd == "list-handlers":
        from limenal.registry import discover_handlers

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

        from limenal.server import (
            CabalCoreCredentialResolver,
            IssuerConfig,
            JWTVerifier,
            SqlitePolicyStore,
            URLJWKSVerifier,
            build_multi_issuer_verifier,
            create_app,
        )

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
                    id=i["id"], jwks_uri=i["jwks_uri"], parent=bool(i.get("parent", False))
                )
                for i in cfg.get("issuer", [])
            ]
            try:
                policy_tool_extras, policy_scope_for = _parse_trust_registry_extra(cfg)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            verifier = build_multi_issuer_verifier(
                issuers, service_audience=service_audience
            )
            parent_issuer = next(i.id for i in issuers if i.parent)
            policy_store = SqlitePolicyStore(args.policy_db, parent_issuer=parent_issuer)
            if policy_scope_for is not None:
                print(
                    f"sovereign scope enforcement: {len(cfg.get('scope_map', {}))} "
                    "handler scope(s) wired from [scope_map]",
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
                jwks_url=args.jwks_url, expected_issuer=args.issuer
            )
        else:
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

        app = create_app(
            jwt_verifier=verifier,
            credential_resolver=credential_resolver,
            policy_store=policy_store,
            policy_scope_for=policy_scope_for,
            policy_tool_extras=policy_tool_extras,
            targets=targets,
        )
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
