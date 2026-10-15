"""logscan: stream log files and flag anomalies.

Detectors:
  - BurstDetector: too many errors inside a sliding time window
  - LatencySpikeDetector: response times far from the running mean (z-score)
  - ErrorRateDetector: time buckets where the error ratio exceeds a threshold
  - SuspiciousPatternDetector: regex patterns (failed logins, SQLi probes, ...)
"""

from logscan.analyzer import Analyzer, Anomaly, analyze_file, analyze_lines
from logscan.detectors import (
    BurstDetector,
    ErrorRateDetector,
    LatencySpikeDetector,
    SuspiciousPatternDetector,
)
from logscan.log_entry import LogEntry, parse_line

__all__ = [
    "Analyzer",
    "Anomaly",
    "BurstDetector",
    "ErrorRateDetector",
    "LatencySpikeDetector",
    "LogEntry",
    "SuspiciousPatternDetector",
    "analyze_file",
    "analyze_lines",
    "parse_line",
]
