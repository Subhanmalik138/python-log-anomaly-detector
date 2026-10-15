"""Command-line interface.

Usage:
    logscan scan access.log
    logscan scan app.log --format json --fail-on-anomaly
    logscan scan app.log --burst-threshold 5 --latency-z 4.0
"""

from __future__ import annotations

import argparse
import json
import sys

from logscan.analyzer import Report, analyze_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logscan",
        description="Stream a log file and report anomalies: error bursts, "
                    "latency spikes, high error rates, suspicious patterns.",
    )
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a log file for anomalies")
    scan.add_argument("logfile", help="path to the log file to scan")
    scan.add_argument("--format", choices=("text", "json"), default="text",
                      help="output format (default: text)")
    scan.add_argument("--fail-on-anomaly", action="store_true",
                      help="exit with status 2 when any anomaly is found")
    scan.add_argument("--burst-window", type=int, default=60,
                      help="burst detector window in seconds (default: 60)")
    scan.add_argument("--burst-threshold", type=int, default=10,
                      help="errors inside the window that trigger a burst (default: 10)")
    scan.add_argument("--latency-z", type=float, default=3.0,
                      help="z-score that flags a latency spike (default: 3.0)")
    scan.add_argument("--rate-threshold", type=float, default=0.5,
                      help="error ratio that flags a time bucket (default: 0.5)")
    return p


def format_text(report: Report) -> str:
    lines = [
        f"Scanned {report.lines} lines: "
        f"{report.errors} errors, {report.warnings} warnings, "
        f"{len(report.anomalies)} anomalies found.",
        "",
    ]
    for a in report.anomalies:
        ts = a.timestamp.isoformat(sep=" ") if a.timestamp else "no timestamp"
        lines.append(f"[{a.severity.upper():>6}] {ts}  {a.detail}")
        for ev in a.evidence[:2]:
            lines.append(f"         evidence: {ev[:160]}")
    if not report.anomalies:
        lines.append("No anomalies detected.")
    return "\n".join(lines)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_file(
            args.logfile,
            burst_window_seconds=args.burst_window,
            burst_threshold=args.burst_threshold,
            latency_z_threshold=args.latency_z,
            error_rate_threshold=args.rate_threshold,
        )
    except FileNotFoundError:
        print(f"logscan: file not found: {args.logfile}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"logscan: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_text(report))

    if args.fail_on_anomaly and report.anomalies:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
