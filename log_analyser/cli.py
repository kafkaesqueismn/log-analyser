"""Command-line entry point: ``python -m log_analyser /var/log/auth.log``."""

from __future__ import annotations

import argparse
import gzip
import sys
from datetime import timedelta
from typing import Iterator, Sequence

from . import __version__
from .detector import detect_brute_force, detect_success_after_failures, successful_logins, summarise
from .parser import parse_lines
from .report import AnalysisResult, render_json, render_text


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyser",
        description="Analyse Linux SSH auth logs for brute-force attacks and suspicious logins.",
    )
    p.add_argument("logfiles", nargs="+", help="auth.log file(s) to analyse; .gz is supported, '-' reads stdin")
    p.add_argument("-t", "--threshold", type=_positive_int, default=5,
                   help="failures from one IP that count as brute force (default: 5)")
    p.add_argument("-w", "--window", type=_positive_int, default=300, metavar="SECONDS",
                   help="time window for brute-force detection (default: 300)")
    p.add_argument("-l", "--lookback", type=_positive_int, default=3600, metavar="SECONDS",
                   help="how far before a login to count failures (default: 3600)")
    p.add_argument("-y", "--year", type=int, default=None,
                   help="year for syslog timestamps, which omit it (default: current year)")
    p.add_argument("--top", type=_positive_int, default=5, help="entries in 'top' lists (default: 5)")
    p.add_argument("--json", action="store_true", help="output JSON instead of a text report")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _read_lines(paths: Sequence[str]) -> Iterator[str]:
    for path in paths:
        if path == "-":
            yield from sys.stdin
        elif path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                yield from f
        else:
            with open(path, encoding="utf-8", errors="replace") as f:
                yield from f


def analyse(lines, threshold=5, window=timedelta(minutes=5), lookback=timedelta(hours=1),
            year=None, top=5) -> AnalysisResult:
    events = list(parse_lines(lines, year=year))
    return AnalysisResult(
        summary=summarise(events, top=top),
        brute_force=detect_brute_force(events, threshold, window),
        logins=successful_logins(events),
        suspicious=detect_success_after_failures(events, threshold, lookback),
        threshold=threshold,
        window=window,
        lookback=lookback,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyse(
            _read_lines(args.logfiles),
            threshold=args.threshold,
            window=timedelta(seconds=args.window),
            lookback=timedelta(seconds=args.lookback),
            year=args.year,
            top=args.top,
        )
    except OSError as e:
        print(f"log-analyser: error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(result))
    else:
        sys.stdout.write(render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
