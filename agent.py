"""CLI for the Android static-analysis harness."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import analyze  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mr-amt")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_parser = sub.add_parser("analyze", help="analyze an apk, xapk, or apks file")
    analyze_parser.add_argument("sample", type=Path)
    analyze_parser.add_argument("--out", type=Path, default=Path("workspace"))
    analyze_parser.add_argument(
        "--facts-only",
        action="store_true",
        help="write the case and stop before the model sessions",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    if not args.sample.is_file():
        print(f"sample not found: {args.sample}", file=sys.stderr)
        return 2
    try:
        report, report_path = asyncio.run(
            analyze(args.sample, args.out, run_agents=not args.facts_only)
        )
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    payload = None if report.verdict is None else report.to_dict()["verdict"]
    print(json.dumps(payload, indent=2))
    print(report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
