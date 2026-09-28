"""
CLI entry point for the PII Log Leak Detector.

Usage:
    pii-scan --source-dir <path> [--log-file <path>] [--fix] [--json]
"""

from __future__ import annotations

import argparse
import sys

from pii_scanner.scanner import Scanner
from pii_scanner.fixer import apply_fixes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pii-scan",
        description="Scan Python source files and log files for PII leaks.",
    )
    parser.add_argument(
        "--source-dir",
        metavar="PATH",
        help="Directory of Python source files to scan.",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="Captured log file to scan.",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Inject safe __repr__ fixes, commit to a new branch, and print PR command.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON instead of plain text.",
    )

    args = parser.parse_args(argv)

    if not args.source_dir and not args.log_file:
        parser.error("Provide at least one of --source-dir or --log-file.")

    scanner = Scanner()
    report = scanner.scan(
        source_dir=args.source_dir,
        log_file=args.log_file,
    )

    if args.json:
        print(report.to_json())
    else:
        print(report.to_text())

    if args.fix and report.leaks:
        if not args.source_dir:
            print("⚠️  --fix requires --source-dir to locate model classes.", file=sys.stderr)
            return 1
        apply_fixes(report.leaks, args.source_dir)

    return 1 if report.leaks else 0


if __name__ == "__main__":
    sys.exit(main())
