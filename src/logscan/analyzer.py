"""Streaming analysis: wire the parser and detectors together.

``analyze_lines`` / ``analyze_file`` take an iterable of raw log lines and
return a :class:`Report`. Everything is single-pass with bounded memory, so
multi-gigabyte logs are fine — lines are never materialized into a list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from logscan.detectors import (
    Anomaly,
    BurstDetector,
    ErrorRateDetector,
    LatencySpikeDetector,
    SuspiciousPatternDetector,
)
from logscan.log_entry import LogEntry, parse_line


@dataclass
class Report:
    anomalies: List[Anomaly] = field(default_factory=list)
    lines: int = 0
    errors: int = 0
    warnings: int = 0
    unparsed: int = 0  # lines with no timestamp and no level

    def to_dict(self) -> dict:
        return {
            "summary": {
                "lines": self.lines,
                "errors": self.errors,
                "warnings": self.warnings,
                "anomalies": len(self.anomalies),
            },
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


class Analyzer:
    """Feed entries in, get a report out."""

    def __init__(
        self,
        burst_window_seconds: int = 60,
        burst_threshold: int = 10,
        latency_z_threshold: float = 3.0,
        latency_min_samples: int = 30,
        error_rate_bucket_seconds: int = 60,
        error_rate_threshold: float = 0.5,
        error_rate_min_requests: int = 10,
    ):
        self.detectors = [
            BurstDetector(burst_window_seconds, burst_threshold),
            LatencySpikeDetector(latency_z_threshold, latency_min_samples),
            ErrorRateDetector(error_rate_bucket_seconds, error_rate_threshold,
                             error_rate_min_requests),
            SuspiciousPatternDetector(),
        ]
        self.report = Report()

    def feed(self, entry: LogEntry) -> List[Anomaly]:
        found: List[Anomaly] = []
        for detector in self.detectors:
            found.extend(detector.observe(entry))
        self.report.lines += 1
        if entry.is_error:
            self.report.errors += 1
        elif entry.is_warning:
            self.report.warnings += 1
        if entry.timestamp is None and entry.level is None:
            self.report.unparsed += 1
        self.report.anomalies.extend(found)
        return found

    def finish(self) -> Report:
        for detector in self.detectors:
            self.report.anomalies.extend(detector.finalize())
        # Sort for readability; entries without timestamps go last.
        self.report.anomalies.sort(
            key=lambda a: (a.timestamp is None, a.timestamp)
        )
        return self.report


def analyze_lines(lines: Iterable[str], **kwargs) -> Report:
    analyzer = Analyzer(**kwargs)
    for line in lines:
        if line.strip():
            analyzer.feed(parse_line(line))
    return analyzer.finish()


def analyze_file(path: str, **kwargs) -> Report:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return analyze_lines(fh, **kwargs)
