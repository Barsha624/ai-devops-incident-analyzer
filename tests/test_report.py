import json
from datetime import UTC, datetime

import pytest

from helpers import at
from incident_analyzer.analyzer import analyze, lines_source
from incident_analyzer.config import AnalyzerConfig
from incident_analyzer.exceptions import ReportWriteError
from incident_analyzer.report import build_report, render_terminal, select_evidence, write_json

FIXED_NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def iso(seconds):
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_result(n=30, config=None):
    config = config or AnalyzerConfig()
    lines = [
        f"{iso(s)} ERROR [api] upstream returned HTTP 502 for GET /orders/{s}" for s in range(n)
    ]
    lines.append(f"{iso(n)} CRITICAL [api] pool exhausted")
    return analyze([lines_source(lines, "app.log")], config), config


def test_report_has_expected_top_level_structure():
    result, config = make_result()
    report = build_report(result, config, generated_at=FIXED_NOW)
    assert report["schema_version"] == "1.0"
    assert report["generated_at"] == "2026-10-31T12:00:00.000Z"
    assert set(report) == {
        "schema_version",
        "tool",
        "generated_at",
        "settings",
        "inputs",
        "summary",
        "incidents",
        "spikes",
        "warnings",
        "ai",
    }
    assert report["ai"] is None


def test_report_is_json_serialisable_and_round_trips():
    result, config = make_result()
    report = build_report(result, config, generated_at=FIXED_NOW)
    assert json.loads(json.dumps(report)) == report


def test_report_is_reproducible_for_same_input():
    first = build_report(*make_result(), generated_at=FIXED_NOW)
    second = build_report(*make_result(), generated_at=FIXED_NOW)
    assert first == second


def test_incident_entry_contains_evidence_and_reasons():
    result, config = make_result()
    incident = build_report(result, config, generated_at=FIXED_NOW)["incidents"][0]
    assert incident["id"] == "INC-001"
    assert incident["severity"] in {"low", "medium", "high", "critical"}
    assert incident["severity_reasons"]
    assert incident["first_seen"].startswith("2026-10-31T09:00:00")
    assert incident["evidence"]
    first = incident["evidence"][0]
    assert first["evidence_id"] == "INC-001-E1"
    assert first["line"] >= 1 and first["source"] == "app.log"
    assert first["rules"]


def test_summary_counts_match_incidents():
    result, config = make_result()
    summary = build_report(result, config, generated_at=FIXED_NOW)["summary"]
    assert summary["incidents"] == 1
    assert sum(summary["incidents_by_severity"].values()) == 1
    assert summary["highest_severity"] is not None
    assert summary["time_range"]["start"].startswith("2026-10-31T09:00:00")


def test_evidence_is_bounded_and_includes_last_finding():
    result, _ = make_result(n=50)
    incident = result.incidents[0]
    chosen = select_evidence(incident, 3)
    assert 1 <= len(chosen) <= 3
    assert len({id(f) for f in chosen}) == len(chosen)
    assert select_evidence(incident, 1)  # limit of one still works


def test_evidence_selection_is_deterministic():
    result, _ = make_result()
    a = [f.event.line_no for f in select_evidence(result.incidents[0], 4)]
    b = [f.event.line_no for f in select_evidence(result.incidents[0], 4)]
    assert a == b


def test_terminal_render_explains_severity():
    result, config = make_result()
    text = render_terminal(build_report(result, config, generated_at=FIXED_NOW))
    assert "INC-001" in text
    assert "base:" in text and "volume:" in text
    assert "evidence" in text
    assert "\033[" not in text  # no colour codes unless requested


def test_terminal_render_color_option():
    result, config = make_result()
    text = render_terminal(build_report(result, config, generated_at=FIXED_NOW), color=True)
    assert "\033[" in text


def test_terminal_render_with_no_incidents():
    config = AnalyzerConfig()
    result = analyze([lines_source([f"{iso(0)} INFO [a] ok"], "x.log")], config)
    text = render_terminal(build_report(result, config, generated_at=FIXED_NOW))
    assert "No incidents detected." in text


def test_write_json_creates_parent_directories(tmp_path):
    result, config = make_result()
    report = build_report(result, config, generated_at=FIXED_NOW)
    target = tmp_path / "nested" / "dir" / "report.json"
    write_json(report, target)
    assert json.loads(target.read_text())["schema_version"] == "1.0"


def test_write_json_reports_failures_clearly(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(ReportWriteError, match="cannot write report"):
        write_json({}, blocker / "report.json")
