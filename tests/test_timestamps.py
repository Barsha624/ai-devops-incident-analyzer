from datetime import UTC, datetime

import pytest

from incident_analyzer.timestamps import format_timestamp, parse_timestamp


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-31T09:30:00Z", datetime(2026, 10, 31, 9, 30, tzinfo=UTC)),
        ("2026-10-31T09:30:00+00:00", datetime(2026, 10, 31, 9, 30, tzinfo=UTC)),
        ("2026-10-31T15:00:00+05:30", datetime(2026, 10, 31, 9, 30, tzinfo=UTC)),
        ("2026-10-31 09:30:00", datetime(2026, 10, 31, 9, 30, tzinfo=UTC)),
        (
            "2026-10-31 09:30:00,123",
            datetime(2026, 10, 31, 9, 30, 0, 123000, tzinfo=UTC),
        ),
        ("31/Oct/2026:09:30:00 +0000", datetime(2026, 10, 31, 9, 30, tzinfo=UTC)),
    ],
)
def test_parses_common_text_formats(value, expected):
    assert parse_timestamp(value) == expected


def test_epoch_seconds_and_milliseconds_agree():
    seconds = parse_timestamp(1793439000)
    millis = parse_timestamp(1793439000000)
    assert seconds == millis
    assert seconds == datetime(2026, 10, 31, 9, 30, tzinfo=UTC)


def test_naive_timestamps_are_assumed_utc():
    parsed = parse_timestamp("2026-10-31 09:30:00")
    assert parsed is not None
    assert parsed.utcoffset().total_seconds() == 0


@pytest.mark.parametrize("value", [None, "", "   ", "not a date", True, [], {}, "2026-13-45"])
def test_garbage_returns_none_instead_of_raising(value):
    assert parse_timestamp(value) is None


def test_format_timestamp_round_trip():
    parsed = parse_timestamp("2026-10-31T09:30:00Z")
    assert format_timestamp(parsed) == "2026-10-31T09:30:00.000Z"
    assert format_timestamp(None) is None
