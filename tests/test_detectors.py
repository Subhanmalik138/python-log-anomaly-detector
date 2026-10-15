from datetime import datetime, timedelta, timezone

import pytest

from logscan.detectors import (
    BurstDetector,
    ErrorRateDetector,
    LatencySpikeDetector,
    SuspiciousPatternDetector,
)
from logscan.log_entry import LogEntry

T0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)


def err(ts, msg="boom"):
    return LogEntry(raw=msg, timestamp=ts, level="ERROR", message=msg)


def test_burst_detector_fires_once_per_burst():
    d = BurstDetector(window_seconds=60, threshold=3)
    out = []
    for i in range(5):
        out.extend(d.observe(err(T0 + timedelta(seconds=i * 10))))
    assert len(out) == 1
    assert out[0].kind == "error_burst"
    assert out[0].severity == "high"

    # No second anomaly while the burst is still active...
    out = d.observe(err(T0 + timedelta(seconds=55)))
    assert out == []

    # ...but a fresh burst later fires again.
    out = d.observe(err(T0 + timedelta(seconds=130)))
    out = d.observe(err(T0 + timedelta(seconds=135)))
    out = d.observe(err(T0 + timedelta(seconds=140)))
    assert len(out) == 1


def test_burst_detector_ignores_missing_timestamps():
    d = BurstDetector(threshold=2)
    assert d.observe(err(None)) == []


def test_burst_detector_rejects_bad_threshold():
    with pytest.raises(ValueError):
        BurstDetector(threshold=0)


def test_latency_spike_detector_flags_outlier():
    d = LatencySpikeDetector(z_threshold=3.0, min_samples=10)
    # Train the baseline with steady traffic.
    for i in range(40):
        e = LogEntry(raw="ok", timestamp=T0 + timedelta(seconds=i), latency_ms=100.0)
        assert d.observe(e) == []
    # A huge spike is flagged...
    spike = LogEntry(raw="slow", timestamp=T0 + timedelta(seconds=41), latency_ms=1200.0)
    out = d.observe(spike)
    assert len(out) == 1
    assert out[0].kind == "latency_spike"
    # ...but normal-ish traffic is not.
    normal = LogEntry(raw="ok", timestamp=T0 + timedelta(seconds=42), latency_ms=105.0)
    assert d.observe(normal) == []


def test_latency_spike_detector_ignores_tiny_latencies():
    d = LatencySpikeDetector(z_threshold=1.0, min_samples=5, min_latency_ms=1000.0)
    for i in range(10):
        d.observe(LogEntry(raw="ok", timestamp=T0 + timedelta(seconds=i), latency_ms=1.0))
    out = d.observe(LogEntry(raw="ok", timestamp=T0 + timedelta(seconds=11), latency_ms=50.0))
    assert out == []


def test_error_rate_detector_flags_bad_bucket():
    d = ErrorRateDetector(bucket_seconds=60, rate_threshold=0.5, min_requests=4)
    out = []
    for i in range(4):
        level = "ERROR" if i < 3 else "INFO"  # 75% error rate
        out.extend(d.observe(LogEntry(raw="x", timestamp=T0 + timedelta(seconds=i), level=level)))
    assert len(out) == 1
    assert out[0].kind == "high_error_rate"
    assert "75%" in out[0].detail or "3/4" in out[0].detail


def test_error_rate_detector_needs_min_requests():
    d = ErrorRateDetector(bucket_seconds=60, rate_threshold=0.5, min_requests=10)
    out = d.observe(err(T0))  # single error, bucket too small to judge
    assert out == []


def test_suspicious_pattern_brute_force():
    d = SuspiciousPatternDetector()
    out = []
    for i in range(6):
        out.extend(
            d.observe(
                LogEntry(raw="failed login for root", timestamp=T0 + timedelta(minutes=i),
                         message="failed login for root from 1.2.3.4")
            )
        )
    assert len(out) == 1
    assert out[0].kind == "brute_force_login"
    assert out[0].severity == "high"


def test_suspicious_pattern_sqli_single_hit():
    d = SuspiciousPatternDetector()
    e = LogEntry(raw="GET /search?q=' OR '1'='1", timestamp=T0,
                 message="GET /search?q=' OR '1'='1")
    out = d.observe(e)
    assert len(out) == 1
    assert out[0].kind == "sql_injection_probe"


def test_suspicious_pattern_ignores_benign_traffic():
    d = SuspiciousPatternDetector()
    out = d.observe(
        LogEntry(raw="GET /index.html 200", timestamp=T0, message="GET /index.html", status=200)
    )
    assert out == []


def test_error_rate_detector_fires_once_per_bucket():
    d = ErrorRateDetector(bucket_seconds=60, rate_threshold=0.5, min_requests=4)
    out = []
    for i in range(8):  # all errors in one bucket
        out.extend(d.observe(err(T0 + timedelta(seconds=i * 5))))
    assert len(out) == 1
    # A fresh bucket later can fire again.
    out2 = []
    t1 = T0 + timedelta(seconds=120)
    for i in range(8):
        out2.extend(d.observe(err(t1 + timedelta(seconds=i * 5))))
    assert len(out2) == 1
