"""Command-line interface: ``injectsweep scan <path> [options]``."""

from __future__ import annotations

import argparse
import sys

from . import __version__, reporters
from .models import Severity
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="injectsweep",
        description="Static linter for prompt-injection payloads hidden in "
                    "documents entering a RAG pipeline (OWASP LLM01).",
    )
    parser.add_argument("--version", action="version", version=f"injectsweep {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--format", "-f", choices=["table", "json", "sarif"],
                      default="table", help="output format (default: table)")
    scan.add_argument("--fail-on", choices=[s.label for s in Severity], default=None,
                      help="exit non-zero if any finding is at/above this severity "
                           "(CI gate). Default: report only, exit 0.")
    scan.add_argument("--no-recursive", action="store_true",
                      help="do not descend into subdirectories")
    scan.add_argument("--output", "-o", default=None,
                      help="write report to a file instead of stdout")
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        report = scan_path(args.path, recursive=not args.no_recursive)
        rendered = reporters.render(report, args.format)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print(f"injectsweep: wrote {args.format} report to {args.output}", file=sys.stderr)
        else:
            print(rendered)

        if args.fail_on:
            threshold = Severity.parse(args.fail_on)
            if report.exceeds(threshold):
                print(
                    f"injectsweep: findings at/above '{args.fail_on}' -> failing (exit 1)",
                    file=sys.stderr,
                )
                return 1
        return 0

    parser.print_help()  # pragma: no cover
    return 2


def main() -> None:  # console_scripts entry point
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
