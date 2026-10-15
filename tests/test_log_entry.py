from datetime import datetime, timezone

from logscan.log_entry import LogEntry, parse_line


def test_apache_error_line():
    e = parse_line(
        '203.0.113.7 - - [15/Oct/2026:10:00:01 +0000] "GET /api/users HTTP/1.1" 500 1234'
    )
    assert e.status == 500
    assert e.is_error
    assert e.level == "ERROR"
    assert e.source == "203.0.113.7"
    assert e.timestamp == datetime(2026, 10, 15, 10, 0, 1, tzinfo=timezone.utc)


def test_apache_404_is_warning_not_error():
    e = parse_line(
        '203.0.113.7 - - [15/Oct/2026:10:00:01 +0000] "GET /nope HTTP/1.1" 404 0'
    )
    assert e.status == 404
    assert not e.is_error
    assert e.is_warning


def test_syslog_style_line():
    e = parse_line("2026-10-15 10:12:33 ERROR database connection lost")
    assert e.level == "ERROR"
    assert e.message == "database connection lost"
    assert e.timestamp == datetime(2026, 10, 15, 10, 12, 33, tzinfo=timezone.utc)


def test_bracketed_syslog_level():
    e = parse_line("2026-10-15 10:12:33 [WARNING] disk usage at 92%")
    assert e.level == "WARNING"


def test_key_value_line():
    e = parse_line('ts=2026-10-15T10:12:33Z level=error msg="db timeout" latency_ms=812 ip=10.0.0.9')
    assert e.level == "ERROR"
    assert e.message == "db timeout"
    assert e.latency_ms == 812.0
    assert e.source == "10.0.0.9"


def test_key_value_status_derives_level():
    e = parse_line('ts=2026-10-15T10:12:33Z status=503 msg="upstream down"')
    assert e.level == "ERROR"
    assert e.is_error


def test_garbage_line_never_raises_and_guesses_level():
    e = parse_line("Traceback (most recent call last): ... KeyError")
    assert e.raw.startswith("Traceback")
    assert e.level == "ERROR" or e.level is None  # keyword guess
    assert isinstance(e, LogEntry)


def test_plain_line_is_not_error():
    e = parse_line("starting worker pool with 4 threads")
    assert not e.is_error
    assert e.message == "starting worker pool with 4 threads"


def test_latency_extracted_from_free_text():
    e = parse_line("2026-10-15 10:12:33 INFO request done latency=2400ms")
    assert e.latency_ms == 2400.0


def test_latency_seconds_converted_to_ms():
    e = parse_line("2026-10-15 10:12:33 INFO request done duration: 1.5s")
    assert e.latency_ms == 1500.0


def test_latency_key_with_unit_suffix():
    e = parse_line("2026-10-15 10:12:33 INFO request ok latency_ms=2400")
    assert e.latency_ms == 2400.0
