import urllib.error
import urllib.request

import pytest

from incident_analyzer.exceptions import LogReadError, ReportWriteError
from incident_analyzer.metrics import (
    MetricsExporter,
    create_server,
    render_metrics,
    write_metrics_file,
)

REPORT = {
    "summary": {
        "events_parsed": 100,
        "malformed_lines": 2,
        "findings_by_kind": {"http_5xx": 7, "timeout": 1},
        "incidents_by_severity": {"low": 0, "medium": 1, "high": 0, "critical": 2},
        "highest_severity": "critical",
    },
    "spikes": [{}, {}],
}


def test_render_contains_expected_samples():
    text = render_metrics(REPORT, analysis_seconds=0.25, now=1_700_000_000)
    assert 'incident_analyzer_incidents{severity="critical"} 2' in text
    assert 'incident_analyzer_incidents{severity="low"} 0' in text  # zeros are exported
    assert 'incident_analyzer_findings{kind="http_5xx"} 7' in text
    assert 'incident_analyzer_findings{kind="error_log"} 0' in text
    assert "incident_analyzer_highest_severity 4" in text
    assert "incident_analyzer_error_spikes 2" in text
    assert "incident_analyzer_analysis_duration_seconds 0.25" in text
    assert "incident_analyzer_last_analysis_timestamp_seconds 1700000000" in text
    assert text.endswith("\n")


def test_every_family_has_help_and_type_lines():
    lines = render_metrics(REPORT).splitlines()
    names = {line.split("{")[0].split(" ")[0] for line in lines if not line.startswith("#")}
    for name in names:
        assert f"# HELP {name} " in "\n".join(lines)
        assert f"# TYPE {name} " in "\n".join(lines)


def test_no_report_yet_exports_only_info_and_failures():
    text = render_metrics(None, failures=3)
    assert "incident_analyzer_analysis_failures_total 3" in text
    assert "incidents" not in text.replace("incident_analyzer_", "")


def test_no_incidents_gives_highest_severity_zero():
    report = {**REPORT, "summary": {**REPORT["summary"], "highest_severity": None}}
    assert "incident_analyzer_highest_severity 0" in render_metrics(report)


def test_output_parses_with_prometheus_client_if_available():
    parser = pytest.importorskip("prometheus_client.parser")
    families = list(parser.text_string_to_metric_families(render_metrics(REPORT)))
    assert {f.name for f in families} >= {"incident_analyzer_incidents", "incident_analyzer_info"}


def test_write_metrics_file_is_atomic_and_readable(tmp_path):
    target = tmp_path / "sub" / "incident.prom"
    write_metrics_file(target, "x 1\n")
    assert target.read_text() == "x 1\n"
    assert not [p for p in target.parent.iterdir() if p.name.endswith(".tmp")]


def test_write_metrics_file_error_is_wrapped(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(ReportWriteError):
        write_metrics_file(blocker / "child.prom", "x 1\n")


def test_exporter_keeps_last_good_numbers_when_a_refresh_fails():
    calls = {"n": 0}

    def analyze_once():
        calls["n"] += 1
        if calls["n"] == 2:
            raise LogReadError("disk gone")
        return REPORT

    exporter = MetricsExporter(analyze_once, interval=1)
    assert exporter.refresh() is True
    assert exporter.refresh() is False
    text = exporter.text
    assert "incident_analyzer_analysis_failures_total 1" in text
    assert 'incident_analyzer_incidents{severity="critical"} 2' in text  # still served


def test_first_refresh_can_fail_fast():
    exporter = MetricsExporter(lambda: (_ for _ in ()).throw(LogReadError("nope")), interval=1)
    with pytest.raises(LogReadError):
        exporter.refresh(raise_errors=True)


def test_http_endpoints():
    exporter = MetricsExporter(lambda: REPORT, interval=1)
    exporter.refresh()
    server = create_server(exporter, "127.0.0.1", 0)
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/metrics", timeout=5) as response:
            assert response.status == 200
            assert response.headers["Content-Type"].startswith("text/plain; version=0.0.4")
            assert b"incident_analyzer_incidents" in response.read()
        with urllib.request.urlopen(f"{base}/healthz", timeout=5) as response:
            assert response.read() == b"ok\n"
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(f"{base}/nope", timeout=5)
        assert err.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_exposition_format_is_valid_without_third_party_libraries():
    """Strict check of the text format; runs even where prometheus_client is absent."""
    import re

    sample = re.compile(
        r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[a-z_]+="[^"\\\n]*"(,[a-z_]+="[^"\\\n]*")*\})? -?\d+(\.\d+)?$'
    )
    for line in render_metrics(REPORT, analysis_seconds=0.123, now=1.5).splitlines():
        assert line.startswith(("# HELP ", "# TYPE ")) or sample.match(line), line


def test_label_values_are_escaped():
    from incident_analyzer.metrics import _format_labels

    assert _format_labels({"v": 'a"b\\c\nd'}) == '{v="a\\"b\\\\c\\nd"}'
