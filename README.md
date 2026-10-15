# logscan — Log Anomaly Detector

Point `logscan` at a log file and it tells you what's wrong: error bursts, latency spikes, time buckets with a bad error ratio, and suspicious security patterns (brute-force logins, SQL-injection probes, path traversal). Single pass, bounded memory — multi-gigabyte logs are fine.

```
$ logscan scan /var/log/app.log

Scanned 140 lines: 12 errors, 7 warnings, 5 anomalies found.

[  HIGH] 2026-10-15 10:00:36+00:00  10 errors in 60s (threshold 10)
         evidence: 2026-10-15 10:00:36 ERROR upstream timeout
[  HIGH] 2026-10-15 11:00:00+00:00  latency 2400ms is far above baseline (mean 95ms, n=120)
         evidence: 2026-10-15 11:00:00 INFO request done latency_ms=2400
```

## How it works

Logs are streamed line by line through a parser and four independent detectors.

**Parsing (total, never raises).** Each line is auto-detected as Apache/nginx access logs, syslog-style timestamped lines, `key=value` structured lines, or raw text (severity guessed from keywords). Lines carry an optional timestamp, level, HTTP status, latency, and source.

**Detectors.** Every detector is a small state machine — `observe(entry)` per line, `finalize()` at end of stream — and keeps bounded memory:

| Detector | What it finds | How |
|---|---|---|
| Burst | ≥ N errors inside a sliding time window | `deque` of error timestamps, debounced to one alert per burst |
| Latency spike | Response time far from the running baseline | z-score against a Welford online mean/variance; a rock-steady baseline with one jump counts as a spike |
| Error rate | Time buckets where error ratio ≥ threshold | per-minute request/error counters, fires once per bucket |
| Suspicious patterns | brute-force logins, SQLi/path-traversal probes, auth-failure floods | regex + sliding-window hit counts, one alert per active burst |

## Design decisions

1. **Streaming with bounded memory.** Detectors store deques, running statistics, or fixed-size counters — never the lines themselves. The analyzer never materializes the log, so a 10 GB file uses the same memory as a 10 KB one.
2. **Score before you learn.** The latency detector evaluates each sample against the baseline *before* folding it in, so a huge spike can't dilute its own z-score. Edge case handled: zero-variance baselines (constant 95 ms traffic, then one 2400 ms request) are flagged instead of dividing by zero.
3. **One alert per incident.** Burst and pattern detectors stay quiet until the window drains; the error-rate detector emits each bucket exactly once. Alert fatigue is a bug, not a feature.
4. **Parsing is total.** Every line yields a `LogEntry`, even garbage. Detectors skip entries missing what they need (no timestamp → no burst detection) rather than crashing.

## Usage

```bash
# requires Python 3.10+
pip install .

logscan scan app.log                          # human-readable summary
logscan scan app.log --format json            # machine-readable report
logscan scan app.log --fail-on-anomaly        # exit 2 if anything found (CI-friendly)

# tune the detectors
logscan scan app.log --burst-window 300 --burst-threshold 25 --latency-z 4.0 --rate-threshold 0.3
```

Use it as a library too:

```python
from logscan import analyze_file

report = analyze_file("app.log", burst_threshold=5)
print(report.to_dict()["summary"])
for anomaly in report.anomalies:
    print(anomaly.severity, anomaly.kind, anomaly.detail)
```

## Run the tests

```bash
python -m pytest        # 31 tests, no dependencies beyond pytest
```

## Tech stack

Python 3.10+, standard library only (argparse, dataclasses, re, datetime). No third-party runtime dependencies.
