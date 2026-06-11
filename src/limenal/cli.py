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

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
