import gzip
import json

import pytest

from incident_analyzer.exceptions import LogReadError
from incident_analyzer.models import Level
from incident_analyzer.reader import ParseStats, parse_file, parse_lines, service_name_from_path
from incident_analyzer.text_parser import extract_http_status


def parse(lines, service="svc"):
    stats = ParseStats(source="test")
    events = list(parse_lines(lines, "test", default_service=service, stats=stats))
    return events, stats


class TestTextFormats:
    def test_standard_format_with_bracketed_service(self):
        events, stats = parse(["2026-10-31T09:30:00Z ERROR [checkout] payment failed"])
        assert len(events) == 1
        event = events[0]
        assert event.service == "checkout"
        assert event.level is Level.ERROR
        assert event.message == "payment failed"
        assert event.timestamp is not None
        assert stats.malformed_lines == 0

    def test_python_logging_style(self):
        line = "2026-10-31 09:30:00,123 - orders - WARNING - slow query"
        events, _ = parse([line])
        assert events[0].service == "orders"
        assert events[0].level is Level.WARN

    def test_service_falls_back_to_default(self):
        events, _ = parse(["2026-10-31T09:30:00Z INFO started"], service="from-filename")
        assert events[0].service == "from-filename"

    def test_logfmt_service_key(self):
        events, _ = parse(["2026-10-31T09:30:00Z ERROR upstream failed service=billing"])
        assert events[0].service == "billing"

    def test_nginx_access_log(self):
        line = '10.0.0.1 - - [31/Oct/2026:09:30:00 +0000] "GET /api/orders/7 HTTP/1.1" 502 120'
        events, _ = parse([line], service="nginx")
        event = events[0]
        assert event.http_status == 502
        assert event.http_method == "GET"
        assert event.http_path == "/api/orders/7"
        assert event.level is Level.ERROR
        assert event.service == "nginx"

    def test_status_extracted_from_message(self):
        events, _ = parse(["2026-10-31T09:30:00Z ERROR upstream returned HTTP 503 for GET /health"])
        assert events[0].http_status == 503
        assert events[0].http_method == "GET"
        assert events[0].http_path == "/health"

    @pytest.mark.parametrize(
        "message",
        ["query returned 500 rows", "retrying in 502 ms", "processed 5000 items", "port 8080"],
    )
    def test_numbers_without_http_cue_are_not_statuses(self, message):
        assert extract_http_status(message) is None


class TestJsonFormats:
    def test_basic_json_record(self):
        line = json.dumps(
            {
                "timestamp": "2026-10-31T09:30:00Z",
                "level": "error",
                "service": "payments",
                "message": "card declined",
            }
        )
        events, _ = parse([line])
        assert events[0].service == "payments"
        assert events[0].level is Level.ERROR

    def test_alternative_field_names(self):
        line = json.dumps({"@timestamp": 1793439000, "severity": "WARNING", "app": "a", "msg": "m"})
        events, _ = parse([line])
        assert events[0].level is Level.WARN
        assert events[0].service == "a"
        assert events[0].message == "m"

    def test_http_fields_and_synthesised_message(self):
        line = json.dumps(
            {"ts": "2026-10-31T09:30:00Z", "status": 502, "method": "get", "path": "/x"}
        )
        events, _ = parse([line])
        assert events[0].http_status == 502
        assert events[0].http_method == "GET"
        assert events[0].message == "GET /x -> 502"

    def test_status_as_string_and_out_of_range(self):
        ok, _ = parse([json.dumps({"level": "error", "message": "m", "status": "503"})])
        bad, _ = parse([json.dumps({"level": "error", "message": "m", "status": 99999})])
        assert ok[0].http_status == 503
        assert bad[0].http_status is None

    def test_stack_trace_field_becomes_detail(self):
        line = json.dumps({"level": "error", "message": "boom", "stack": "a\nb\nValueError: x"})
        events, _ = parse([line])
        assert events[0].detail_tail == "ValueError: x"

    def test_json_array_file(self, tmp_path):
        path = tmp_path / "api.json"
        path.write_text(json.dumps([{"level": "error", "message": "x"}, "not-an-object"]))
        stats = ParseStats(source=str(path))
        events = list(parse_file(path, stats=stats))
        assert len(events) == 1
        assert stats.malformed_lines == 1
        assert events[0].service == "api"


class TestMalformedInput:
    def test_bad_lines_are_counted_not_fatal(self):
        lines = [
            "2026-10-31T09:30:00Z ERROR [a] first",
            "{this is not json",
            "total garbage",
            "[1, 2, 3]",
            '{"unrelated": true}',
            "2026-10-31T09:30:01Z ERROR [a] second",
        ]
        events, stats = parse(lines)
        assert [e.message for e in events] == ["first", "second"]
        assert stats.malformed_lines == 4
        assert stats.lines_read == 6
        assert len(stats.malformed_samples) == 4
        assert stats.malformed_ratio == pytest.approx(4 / 6)

    def test_blank_lines_are_ignored_silently(self):
        events, stats = parse(["", "   ", "2026-10-31T09:30:00Z INFO [a] ok", ""])
        assert len(events) == 1
        assert stats.malformed_lines == 0

    def test_garbage_before_any_event_is_malformed(self):
        _, stats = parse(["    indented but nothing before it"])
        assert stats.malformed_lines == 1

    def test_unparseable_timestamp_keeps_the_event(self):
        events, _ = parse(['{"timestamp": "yesterday-ish", "level": "error", "message": "m"}'])
        assert len(events) == 1
        assert events[0].timestamp is None

    def test_very_long_message_is_truncated(self):
        events, _ = parse(["2026-10-31T09:30:00Z ERROR [a] " + "x" * 50_000])
        assert len(events[0].message) <= 2000
        assert len(events[0].raw) <= 1000


class TestContinuationLines:
    def test_python_traceback_is_attached_to_its_event(self):
        lines = [
            "2026-10-31T09:30:00Z ERROR [orders] unhandled exception",
            "Traceback (most recent call last):",
            '  File "app.py", line 10, in handler',
            "    total = price / qty",
            "ZeroDivisionError: division by zero",
            "2026-10-31T09:30:01Z INFO [orders] next request",
        ]
        events, stats = parse(lines)
        assert len(events) == 2
        assert events[0].detail_tail == "ZeroDivisionError: division by zero"
        assert "Traceback" in events[0].details
        assert stats.malformed_lines == 0

    def test_java_style_trace(self):
        lines = [
            "2026-10-31T09:30:00Z ERROR [api] request failed java.lang.IllegalStateException",
            "\tat com.example.Handler.run(Handler.java:42)",
            "Caused by: java.io.IOException: broken pipe",
            "\t... 12 more",
        ]
        events, stats = parse(lines)
        assert len(events) == 1
        assert stats.malformed_lines == 0

    def test_detail_storage_is_bounded(self):
        lines = ["2026-10-31T09:30:00Z ERROR [a] boom"] + ["    frame"] * 1000 + ["ValueError: end"]
        events, _ = parse(lines)
        assert events[0].details.count("\n") < 100
        assert events[0].detail_tail == "ValueError: end"


class TestFiles:
    def test_missing_file_raises_clear_error(self, tmp_path):
        with pytest.raises(LogReadError, match="not found"):
            list(parse_file(tmp_path / "nope.log"))

    def test_directory_raises_clear_error(self, tmp_path):
        with pytest.raises(LogReadError, match="directory"):
            list(parse_file(tmp_path))

    def test_gzip_file(self, tmp_path):
        path = tmp_path / "svc.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write("2026-10-31T09:30:00Z ERROR [x] boom\n")
        events = list(parse_file(path))
        assert len(events) == 1

    def test_corrupt_gzip_raises_read_error(self, tmp_path):
        path = tmp_path / "bad.log.gz"
        path.write_bytes(b"this is not gzip data")
        with pytest.raises(LogReadError):
            list(parse_file(path))

    def test_invalid_utf8_does_not_crash(self, tmp_path):
        path = tmp_path / "svc.log"
        path.write_bytes(b"2026-10-31T09:30:00Z ERROR [x] caf\xe9 broke\n")
        events = list(parse_file(path))
        assert len(events) == 1
        assert "caf" in events[0].message

    def test_empty_file_yields_nothing(self, tmp_path):
        path = tmp_path / "empty.log"
        path.write_text("")
        stats = ParseStats(source=str(path))
        assert list(parse_file(path, stats=stats)) == []
        assert stats.lines_read == 0

    def test_service_name_from_path(self, tmp_path):
        assert service_name_from_path(tmp_path / "payments-api.log.gz") == "payments-api"
        assert service_name_from_path(tmp_path / "web.jsonl") == "web"
