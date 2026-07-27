"""Administrative CLI for local operators."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from anva import __version__
from anva.entrypoints.bootstrap import configure_django


def build_parser() -> argparse.ArgumentParser:
    """Build the stable CLI contract."""
    parser = argparse.ArgumentParser(prog="anva", description="Operate an Anva installation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Check required service dependencies")
    subparsers.add_parser("version", help="Print the installed Anva version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one CLI command and return a process exit code."""
    arguments = build_parser().parse_args(argv)
    if arguments.command == "version":
        print(__version__)
        return 0

    configure_django()
    from anva.foundation.services import readiness_status

    status = readiness_status()
    print(json.dumps(status.as_dict(), sort_keys=True))
    return 0 if status.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
