"""Anomaly detectors.

Every detector is a small state machine with the same contract:

- ``observe(entry)`` — feed one :class:`LogEntry`; returns anomalies found
  *because of this entry* (often empty).
- ``finalize()`` — called at end of stream; returns anomalies that need the
  whole stream (bucket rates) or pending state to be flushed.

Detectors keep bounded memory: sliding-window deques, running statistics, or
fixed-size counters. They must never raise on malformed entries — a missing
timestamp or level just means the entry is skipped by that detector.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Tuple

from logscan.log_entry import LogEntry


@dataclass
class Anomaly:
    detector: str
    kind: str
    severity: str  # "low" | "medium" | "high"
    timestamp: Optional[datetime]
    detail: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "kind": self.kind,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "detail": self.detail,
            "evidence": self.evidence,
        }


class BurstDetector:
    """Too many errors inside a sliding time window (e.g. 10 errors in 60s).

    Entries without a timestamp are skipped — a burst is meaningless without
    ordering. Each burst emits exactly one anomaly when the threshold is first
    crossed, then stays quiet until the window drains below threshold again.
    """

    def __init__(self, window_seconds: int = 60, threshold: int = 10):
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._errors: Deque[datetime] = deque()
        self._in_burst = False

    def observe(self, entry: LogEntry) -> List[Anomaly]:
        if not entry.is_error or entry.timestamp is None:
            return []
        now = entry.timestamp
        self._errors.append(now)
        while self._errors and now - self._errors[0] > self.window:
            self._errors.popleft()

        anomalies: List[Anomaly] = []
        if len(self._errors) >= self.threshold and not self._in_burst:
            self._in_burst = True
            anomalies.append(
                Anomaly(
                    detector="burst",
                    kind="error_burst",
                    severity="high",
                    timestamp=now,
                    detail=(
                        f"{len(self._errors)} errors in "
                        f"{self.window.total_seconds():.0f}s "
                        f"(threshold {self.threshold})"
                    ),
                    evidence=[entry.raw],
                )
            )
        elif len(self._errors) < self.threshold:
            self._in_burst = False
        return anomalies

    def finalize(self) -> List[Anomaly]:
        return []


class LatencySpikeDetector:
    """Response times far from the running mean, measured in z-scores.

    Uses Welford's online algorithm so memory stays O(1). The first
    ``min_samples`` observations only train the baseline. ``z_threshold=3``
    catches genuine outliers without flagging normal jitter; spikes below
    ``min_latency_ms`` are ignored (a 5ms request can be "3 sigma slow" and
    still be fine).
    """

    def __init__(self, z_threshold: float = 3.0, min_samples: int = 30,
                 min_latency_ms: float = 100.0):
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        self.min_latency_ms = min_latency_ms
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0

    def observe(self, entry: LogEntry) -> List[Anomaly]:
        if entry.latency_ms is None:
            return []
        x = entry.latency_ms
        anomalies: List[Anomaly] = []

        # Score against the baseline *before* folding this sample in,
        # otherwise a huge spike dilutes its own z-score.
        if self._n >= self.min_samples and x >= self.min_latency_ms:
            variance = self._m2 / self._n
            std = math.sqrt(variance) if variance > 0 else 0.0
            if std > 0:
                z = (x - self._mean) / std
                sigma = f"{z:.1f} sigma"
            elif x > self._mean:
                # Rock-steady baseline: any jump is the clearest possible spike.
                z = float("inf")
                sigma = "far"
            else:
                z = None

            if z is not None and z >= self.z_threshold:
                severity = "high" if z >= 2 * self.z_threshold else "medium"
                anomalies.append(
                    Anomaly(
                        detector="latency",
                        kind="latency_spike",
                        severity=severity,
                        timestamp=entry.timestamp,
                        detail=(
                            f"latency {x:.0f}ms is {sigma} above baseline "
                            f"(mean {self._mean:.0f}ms, n={self._n})"
                        ),
                        evidence=[entry.raw],
                    )
                )

        # Welford update.
        self._n += 1
        delta = x - self._mean
        self._mean += delta / self._n
        self._m2 += delta * (x - self._mean)
        return anomalies

    def finalize(self) -> List[Anomaly]:
        return []


class ErrorRateDetector:
    """Time buckets where the error ratio exceeds a threshold.

    Counts requests vs errors per ``bucket_seconds`` window and flags buckets
    with ``errors/requests >= rate_threshold`` once the bucket closes. Needs
    at least ``min_requests`` per bucket so one lonely failing request does
    not trigger an alert.
    """

    def __init__(self, bucket_seconds: int = 60, rate_threshold: float = 0.5,
                 min_requests: int = 10):
        self.bucket_seconds = bucket_seconds
        self.rate_threshold = rate_threshold
        self.min_requests = min_requests
        self._buckets: Dict[datetime, Tuple[int, int]] = defaultdict(lambda: (0, 0))
        self._emitted: Dict[datetime, None] = {}  # buckets already alerted on

    def _bucket_start(self, ts: datetime) -> datetime:
        epoch = int(ts.timestamp())
        start = epoch - (epoch % self.bucket_seconds)
        return datetime.fromtimestamp(start, tz=ts.tzinfo)

    def _prune(self, current: datetime) -> None:
        # Keep at most ~10 buckets of alert history so memory stays bounded.
        cutoff = current - timedelta(seconds=10 * self.bucket_seconds)
        for start in [s for s in self._buckets if s < cutoff]:
            del self._buckets[start]
        for start in [s for s in self._emitted if s < cutoff]:
            del self._emitted[start]

    def observe(self, entry: LogEntry) -> List[Anomaly]:
        if entry.timestamp is None:
            return []
        start = self._bucket_start(entry.timestamp)
        requests, errors = self._buckets[start]
        requests += 1
        if entry.is_error:
            errors += 1
        self._buckets[start] = (requests, errors)
        self._prune(start)

        anomalies: List[Anomaly] = []
        # Each bucket fires at most once, the moment it crosses the threshold.
        if (
            start not in self._emitted
            and requests >= self.min_requests
            and errors / requests >= self.rate_threshold
        ):
            self._emitted[start] = None
            rate = errors / requests
            anomalies.append(
                Anomaly(
                    detector="error_rate",
                    kind="high_error_rate",
                    severity="high" if rate >= 0.9 else "medium",
                    timestamp=start,
                    detail=(
                        f"{errors}/{requests} requests errored "
                        f"({rate:.0%}) in the "
                        f"{self.bucket_seconds}s bucket starting {start.isoformat()}"
                    ),
                    evidence=[entry.raw],
                )
            )
        return anomalies

    def finalize(self) -> List[Anomaly]:
        return []


# pattern name -> (regex, threshold in window, window, severity)
_SUSPICIOUS: Dict[str, Tuple[re.Pattern, int, timedelta, str]] = {
    "brute_force_login": (
        re.compile(r"(failed (log ?in|auth(entication)?)|invalid password|login failed)", re.IGNORECASE),
        5, timedelta(minutes=5), "high",
    ),
    "sql_injection_probe": (
        re.compile(r"(\bunion\b.*\bselect\b|'\s*or\s*'?\d|--|;.*drop\b)", re.IGNORECASE),
        1, timedelta(minutes=10), "high",
    ),
    "auth_failures": (
        re.compile(r"\b401\b|\b403\b|unauthorized|forbidden", re.IGNORECASE),
        20, timedelta(minutes=5), "medium",
    ),
    "path_traversal_probe": (
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/self)", re.IGNORECASE),
        1, timedelta(minutes=10), "high",
    ),
}


class SuspiciousPatternDetector:
    """Regex-based security patterns with sliding-window counting.

    A single SQL-injection probe is worth flagging (threshold 1); brute-force
    logins need repetition before they mean anything (threshold 5 in 5 min).
    Debounced like BurstDetector: one anomaly per active burst.
    """

    def __init__(self, patterns: Optional[Dict[str, Tuple[re.Pattern, int, timedelta, str]]] = None):
        self.patterns = patterns or _SUSPICIOUS
        self._hits: Dict[str, Deque[datetime]] = {name: deque() for name in self.patterns}
        self._active: Dict[str, bool] = {name: False for name in self.patterns}

    def observe(self, entry: LogEntry) -> List[Anomaly]:
        anomalies: List[Anomaly] = []
        haystack = f"{entry.message} {entry.raw}"
        for name, (regex, threshold, window, severity) in self.patterns.items():
            if not regex.search(haystack):
                continue
            now = entry.timestamp
            if now is None:
                # No timestamp: can only fire single-hit patterns.
                if threshold == 1 and not self._active[name]:
                    self._active[name] = True
                    anomalies.append(self._anomaly(name, severity, None, entry))
                continue
            hits = self._hits[name]
            hits.append(now)
            while hits and now - hits[0] > window:
                hits.popleft()
            if len(hits) >= threshold and not self._active[name]:
                self._active[name] = True
                anomalies.append(
                    self._anomaly(
                        name, severity, now, entry,
                        extra=f" ({len(hits)} hits in {window})",
                    )
                )
            elif len(hits) < threshold:
                self._active[name] = False
        return anomalies

    @staticmethod
    def _anomaly(name: str, severity: str, ts: Optional[datetime],
                 entry: LogEntry, extra: str = "") -> Anomaly:
        return Anomaly(
            detector="suspicious_pattern",
            kind=name,
            severity=severity,
            timestamp=ts,
            detail=f"suspicious pattern '{name}' detected{extra}",
            evidence=[entry.raw],
        )

    def finalize(self) -> List[Anomaly]:
        return []
