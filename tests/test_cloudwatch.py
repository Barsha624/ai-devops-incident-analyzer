from datetime import UTC, datetime, timedelta

import pytest

from helpers import T0
from incident_analyzer import cloudwatch
from incident_analyzer.analyzer import analyze
from incident_analyzer.cloudwatch import fetch_records, parse_since, records_to_source
from incident_analyzer.config import AnalyzerConfig
from incident_analyzer.exceptions import ConfigError, SourceError

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def ms(seconds):
    return int((T0 + timedelta(seconds=seconds)).timestamp() * 1000)


class FakeLogs:
    """Mimics boto3's CloudWatch Logs client: pages of events with nextToken."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        index = 0 if "nextToken" not in kwargs else int(kwargs["nextToken"])
        page = {"events": self.pages[index]}
        if index + 1 < len(self.pages):
            page["nextToken"] = str(index + 1)
        return page


def event(seconds, message, stream="s1"):
    return {"timestamp": ms(seconds), "message": message, "logStreamName": stream}


@pytest.mark.parametrize(
    ("text", "delta"),
    [("30s", 30), ("15m", 900), ("2h", 7200), ("1d", 86400), (" 5 m ", 300)],
)
def test_parse_since_relative(text, delta):
    assert parse_since(text, NOW) == NOW - timedelta(seconds=delta)


def test_parse_since_iso_and_naive_is_utc():
    assert parse_since("2026-10-31T09:00:00Z") == datetime(2026, 10, 31, 9, tzinfo=UTC)
    assert parse_since("2026-10-31T09:00:00") == datetime(2026, 10, 31, 9, tzinfo=UTC)


@pytest.mark.parametrize("bad", ["", "soon", "10x", "-5m"])
def test_parse_since_rejects_garbage(bad):
    with pytest.raises(ConfigError, match="--since"):
        parse_since(bad)


def test_pagination_collects_every_page_and_passes_filters():
    client = FakeLogs([[event(0, "a"), event(1, "b")], [event(2, "c")]])
    records, truncated = fetch_records(
        "/aws/ecs/app",
        start=NOW - timedelta(hours=1),
        end=NOW,
        filter_pattern="ERROR",
        client=client,
    )
    assert [r.message for r in records] == ["a", "b", "c"] and not truncated
    assert client.calls[0]["filterPattern"] == "ERROR"
    assert client.calls[0]["logGroupName"] == "/aws/ecs/app"
    assert client.calls[1]["nextToken"] == "1"


def test_max_events_truncates_and_says_so():
    client = FakeLogs([[event(i, f"m{i}") for i in range(5)], [event(9, "later")]])
    records, truncated = fetch_records(
        "g", start=NOW - timedelta(hours=1), end=NOW, max_events=3, client=client
    )
    assert len(records) == 3 and truncated


def test_exactly_max_events_with_nothing_more_is_not_truncated():
    client = FakeLogs([[event(i, f"m{i}") for i in range(3)]])
    _, truncated = fetch_records("g", start=NOW, end=NOW, max_events=3, client=client)
    assert not truncated


class FakeAwsError(Exception):
    def __init__(self, code):
        super().__init__(f"An error occurred ({code})")
        self.response = {"Error": {"Code": code}}


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("ResourceNotFoundException", "log group not found"),
        ("AccessDeniedException", "logs:FilterLogEvents"),
        ("ThrottlingException", "throttled"),
        ("ExpiredTokenException", "expired"),
    ],
)
def test_aws_errors_become_actionable_source_errors(monkeypatch, code, expected):
    monkeypatch.setattr(cloudwatch, "_aws_error_types", lambda: (FakeAwsError,))

    class Failing:
        def filter_log_events(self, **kwargs):
            raise FakeAwsError(code)

    with pytest.raises(SourceError, match=expected):
        fetch_records("g", start=NOW, end=NOW, client=Failing())


def test_missing_boto3_gives_install_hint(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith(("boto3", "botocore")):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SourceError, match=r"pip install"):
        fetch_records("g", start=NOW, end=NOW)


def test_real_botocore_errors_are_wrapped():
    botocore = pytest.importorskip("botocore.exceptions")

    class Failing:
        def filter_log_events(self, **kwargs):
            raise botocore.ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, "FilterLogEvents"
            )

    with pytest.raises(SourceError, match="log group not found"):
        fetch_records("g", start=NOW, end=NOW, client=Failing())


# ------------------------------------------------------------------ records -> analysis


def test_records_flow_through_the_normal_pipeline():
    messages = [
        event(
            i * 5,
            f"2026-10-31T09:00:{i * 5:02d}Z ERROR [checkout] upstream returned HTTP 502 for GET /x",
        )
        for i in range(6)
    ]
    records, _ = fetch_records("/aws/ecs/checkout", start=NOW, end=NOW, client=FakeLogs([messages]))
    stats, events = records_to_source(records, "/aws/ecs/checkout")
    result = analyze([(stats, events)], AnalyzerConfig())
    assert stats.source == "cloudwatch:/aws/ecs/checkout"
    assert len(result.incidents) == 1 and result.incidents[0].service == "checkout"


def test_lines_without_a_timestamp_fall_back_to_ingestion_time():
    records, _ = fetch_records(
        "/aws/lambda/fn",
        start=NOW,
        end=NOW,
        client=FakeLogs([[event(30, '{"level": "error", "message": "boom"}')]]),
    )
    stats, events = records_to_source(records, "/aws/lambda/fn")
    (parsed,) = list(events)
    assert parsed.timestamp == T0 + timedelta(seconds=30)
    assert parsed.service == "fn"  # last segment of the log group


def test_multiline_message_keeps_its_stack_trace():
    message = (
        "2026-10-31T09:00:00Z ERROR [api] Unhandled\n"
        "Traceback (most recent call last):\n  File x\nKeyError: 'a'"
    )
    records, _ = fetch_records("g", start=NOW, end=NOW, client=FakeLogs([[event(0, message)]]))
    _, events = records_to_source(records, "g")
    (parsed,) = list(events)
    assert "KeyError" in parsed.detail_tail


def test_empty_fetch_is_not_an_error():
    stats, events = records_to_source([], "g")
    assert list(events) == [] and stats.events_parsed == 0
