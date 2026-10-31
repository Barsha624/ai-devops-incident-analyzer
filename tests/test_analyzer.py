import pytest

from helpers import at
from incident_analyzer.analyzer import analyze, file_source, lines_source
from incident_analyzer.config import AnalyzerConfig
from incident_analyzer.exceptions import MalformedLogError


def iso(seconds):
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


def line(seconds, level="ERROR", service="api", message="boom"):
    return f"{iso(seconds)} {level} [{service}] {message}"


def run(lines, config=None, **kwargs):
    return analyze([lines_source(lines, "test.log")], config or AnalyzerConfig(), **kwargs)


def test_end_to_end_incident_from_text_lines():
    lines = [line(0, "INFO", message="start")] + [
        line(s, message="HTTP 502 for GET /x") for s in (5, 10, 15, 20)
    ]
    result = run(lines)
    assert result.events_parsed == 5
    assert result.findings_total == 4
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.service == "api"
    assert incident.severity.label in {"low", "medium", "high", "critical"}
    assert result.log_start == at(0) and result.log_end == at(20)


def test_healthy_log_has_no_incidents():
    result = run([line(s, "INFO", message="ok") for s in range(0, 100, 10)])
    assert result.findings_total == 0
    assert result.incidents == []
    assert result.warnings == []


def test_malformed_lines_do_not_stop_analysis():
    lines = [line(0), "garbage", line(1), "{broken json", line(2), line(3)]
    result = run(lines)
    assert result.malformed_lines == 2
    assert result.findings_total == 4
    assert len(result.incidents) == 1


def test_strict_mode_raises_on_malformed_lines():
    with pytest.raises(MalformedLogError, match="test.log: 1"):
        run([line(0), "garbage"], strict=True)


def test_strict_mode_passes_clean_input():
    run([line(0), line(1)], strict=True)


def test_warning_when_most_lines_are_not_understood():
    result = run(["nonsense " + str(i) for i in range(10)] + [line(0)])
    assert any("not understood" in w for w in result.warnings)


def test_warning_when_nothing_parses():
    result = run(["nonsense"])
    assert any("no log events" in w for w in result.warnings)


def test_warning_for_undated_findings():
    result = run(['{"level": "error", "message": "no time here"}'] * 3)
    assert any("no parseable timestamp" in w for w in result.warnings)
    assert len(result.incidents) == 1


def test_findings_cap_is_enforced_and_reported():
    config = AnalyzerConfig()
    config.analysis.max_findings = 5
    result = run([line(s) for s in range(20)], config)
    assert result.findings_total == 20
    assert sum(i.count for i in result.incidents) == 5
    assert any("capped" in w for w in result.warnings)


def test_multiple_sources_are_merged_into_one_timeline(tmp_path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("\n".join(line(s, service="a") for s in range(0, 30, 10)) + "\n")
    b.write_text("\n".join(line(s, service="b") for s in range(5, 35, 10)) + "\n")
    result = analyze([file_source(a), file_source(b)], AnalyzerConfig())
    assert {i.service for i in result.incidents} == {"a", "b"}
    assert result.incidents[0].related_incident_ids  # overlap hint


def test_critical_services_setting_changes_severity():
    lines = [line(s, message="HTTP 502 for GET /x") for s in range(0, 30, 10)]
    plain = run(lines).incidents[0].severity_score
    config = AnalyzerConfig()
    config.analysis.critical_services = ("api",)
    boosted = run(lines, config).incidents[0].severity_score
    assert boosted == plain + 1


def test_analysis_is_deterministic():
    lines = [line(s, message="HTTP 502 for GET /x") for s in range(0, 600, 7)]
    first = run(lines).incidents[0]
    second = run(lines).incidents[0]
    assert (first.id, first.severity_score, first.count) == (
        second.id,
        second.severity_score,
        second.count,
    )
