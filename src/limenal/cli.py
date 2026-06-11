"""Tiny CLI — `limenal --version`, `limenal list-handlers`.

The real serve mode comes in Phase 1.5 when the MCP HTTP/SSE server
lands.
"""

from __future__ import annotations

import argparse
import sys


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
        "--issuer", default="cabal-core", help="Expected `iss` claim."
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
            URLJWKSVerifier,
            create_app,
        )

        verifier = None
        if args.jwks_url:
            verifier = URLJWKSVerifier(
                jwks_url=args.jwks_url, expected_issuer=args.issuer
            )
        else:
            print(
                "warning: --jwks-url not set; tools/list and tools/call will reject every request",
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

        app = create_app(
            jwt_verifier=verifier,
            credential_resolver=credential_resolver,
        )
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
