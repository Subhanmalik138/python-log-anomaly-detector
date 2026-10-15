import json

from logscan.analyzer import analyze_lines
from logscan.cli import main


def test_analyzer_counts_and_finds_burst():
    lines = [
        f"2026-10-15 10:00:{i:02d} ERROR something broke" for i in range(12)
    ]
    report = analyze_lines(lines, burst_threshold=10)
    assert report.lines == 12
    assert report.errors == 12
    assert any(a.kind == "error_burst" for a in report.anomalies)


def test_analyzer_empty_log_is_clean():
    report = analyze_lines([])
    assert report.lines == 0
    assert report.anomalies == []


def test_analyzer_blank_lines_skipped():
    report = analyze_lines(["", "   ", "2026-10-15 10:00:00 INFO ok"])
    assert report.lines == 1


def test_analyzer_mixed_formats():
    lines = [
        '203.0.113.7 - - [15/Oct/2026:10:00:01 +0000] "GET /ok HTTP/1.1" 200 12',
        "2026-10-15 10:00:02 WARNING cache miss rate high",
        'ts=2026-10-15T10:00:03Z level=error latency_ms=940 msg="slow query"',
    ]
    report = analyze_lines(lines, burst_threshold=100)
    assert report.lines == 3
    assert report.errors == 1
    assert report.warnings == 1


def test_report_to_dict_is_json_serializable():
    report = analyze_lines(["2026-10-15 10:00:00 ERROR x"] * 12, burst_threshold=10)
    payload = json.dumps(report.to_dict())
    assert "error_burst" in payload


def test_cli_missing_file(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "nope.log")])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_cli_json_output(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("2026-10-15 10:00:00 INFO all good\n")
    rc = main(["scan", str(log), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["lines"] == 1


def test_cli_fail_on_anomaly(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("".join(f"2026-10-15 10:00:{i:02d} ERROR broken\n" for i in range(12)))
    rc = main(["scan", str(log), "--burst-threshold", "10", "--fail-on-anomaly"])
    assert rc == 2


def test_cli_text_output_mentions_summary(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("2026-10-15 10:00:00 INFO all good\n")
    rc = main(["scan", str(log)])
    assert rc == 0
    assert "1 lines" in capsys.readouterr().out
