"""Log line parsing.

Auto-detects a handful of common formats and normalizes them into a
:class:`LogEntry`:

- Apache / nginx combined access logs (status code driven)
- Syslog-style timestamped lines: ``2026-10-15 10:12:33 ERROR message``
- ``key=value`` structured lines (e.g. ``level=error msg="db timeout" latency_ms=812``)
- Anything else: raw message, severity guessed from keywords

Parsing is total: every line produces a LogEntry, even garbage. Downstream
detectors must cope with entries that have no timestamp or level.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)
# 2026-10-15 10:12:33 [LEVEL] message  /  2026-10-15T10:12:33Z LEVEL message
_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?:\[(?P<level>[A-Z]+)\]|(?P<level2>[A-Z]+))\s+(?P<msg>.*)$"
)
_KV_RE = re.compile(r'(?P<key>\w+)=("(?P<quoted>[^"]*)"|(?P<plain>\S+))')

_GUESS_LEVEL_RE = re.compile(
    r"\b(critical|fatal|error|failed?|exception|traceback|denied|timeout)\b",
    re.IGNORECASE,
)

# latency=812ms / latency_ms=812 / duration: 1.2s / response_time=95 — buried in free text.
_LATENCY_IN_TEXT_RE = re.compile(
    r"(?:latency|duration|response[_\s-]?time)(?:[_-](?P<keyunit>ms|s))?"
    r"[_=:\s]+(?P<val>\d+(?:\.\d+)?)\s*(?P<unit>ms|s)?",
    re.IGNORECASE,
)


def _latency_from_text(text: str) -> Optional[float]:
    match = _LATENCY_IN_TEXT_RE.search(text)
    if not match:
        return None
    value = float(match.group("val"))
    unit = (match.group("keyunit") or match.group("unit") or "ms").lower()
    return value * 1000.0 if unit == "s" else value

_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%fZ",
)


@dataclass
class LogEntry:
    """One normalized log line."""

    raw: str
    timestamp: Optional[datetime] = None
    level: Optional[str] = None
    message: str = ""
    status: Optional[int] = None
    latency_ms: Optional[float] = None
    source: Optional[str] = None  # IP, host, or user the line mentions
    extra: dict = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        if self.status is not None:
            return self.status >= 500
        return self.level in ("ERROR", "CRITICAL")

    @property
    def is_warning(self) -> bool:
        if self.status is not None:
            return 400 <= self.status < 500
        return self.level == "WARNING"


def _parse_timestamp(text: str) -> Optional[datetime]:
    text = text.strip()
    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    # Apache format: 10/Oct/2000:13:55:36 -0700
    try:
        dt = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _status_to_level(status: int) -> str:
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


def parse_line(line: str) -> LogEntry:
    """Parse a single log line into a :class:`LogEntry` (never raises)."""
    raw = line.rstrip("\n")

    apache = _APACHE_RE.match(raw)
    if apache:
        status = int(apache.group("status"))
        return LogEntry(
            raw=raw,
            timestamp=_parse_timestamp(apache.group("ts")),
            level=_status_to_level(status),
            message=apache.group("request"),
            status=status,
            source=apache.group("ip"),
        )

    syslog = _SYSLOG_RE.match(raw)
    if syslog and (syslog.group("level") or syslog.group("level2")) in _LEVELS:
        level = syslog.group("level") or syslog.group("level2")
        message = syslog.group("msg")
        return LogEntry(
            raw=raw,
            timestamp=_parse_timestamp(syslog.group("ts")),
            level=level,
            message=message,
            latency_ms=_latency_from_text(message),
        )

    pairs = {m.group("key"): (m.group("quoted") or m.group("plain")) for m in _KV_RE.finditer(raw)}
    if pairs and any(k in pairs for k in ("level", "msg", "message", "ts", "timestamp")):
        level = (pairs.get("level") or "").upper() or None
        message = pairs.get("msg") or pairs.get("message") or ""
        latency = pairs.get("latency_ms") or pairs.get("latency") or pairs.get("duration_ms")
        try:
            latency_ms = float(str(latency).rstrip("ms")) if latency is not None else None
        except ValueError:
            latency_ms = None
        ts_text = pairs.get("ts") or pairs.get("timestamp") or pairs.get("time")
        try:
            status = int(pairs["status"]) if "status" in pairs else None
        except ValueError:
            status = None
        if status is not None and level is None:
            level = _status_to_level(status)
        return LogEntry(
            raw=raw,
            timestamp=_parse_timestamp(ts_text) if ts_text else None,
            level=level,
            message=message,
            status=status,
            latency_ms=latency_ms,
            source=pairs.get("ip") or pairs.get("host") or pairs.get("user"),
            extra={k: v for k, v in pairs.items()
                   if k not in ("level", "msg", "message", "ts", "timestamp",
                                "time", "status", "latency_ms", "latency",
                                "duration_ms", "ip", "host", "user")},
        )

    # Fallback: raw text, severity guessed from keywords.
    guessed = None
    if _GUESS_LEVEL_RE.search(raw):
        lowered = raw.lower()
        guessed = "CRITICAL" if ("critical" in lowered or "fatal" in lowered) else "ERROR"
    return LogEntry(raw=raw, level=guessed, message=raw,
                    latency_ms=_latency_from_text(raw))
