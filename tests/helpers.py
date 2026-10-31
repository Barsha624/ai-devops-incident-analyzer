"""Tiny builders so tests read like the scenario they describe."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from incident_analyzer.models import Level, LogEvent

T0 = datetime(2026, 10, 31, 9, 0, 0, tzinfo=UTC)


def at(seconds: float) -> datetime:
    """``T0`` plus an offset, so tests can say at(90) instead of building datetimes."""
    return T0 + timedelta(seconds=seconds)


def make_event(
    *,
    t: float | None = 0,
    level: Level | None = Level.ERROR,
    service: str = "svc",
    message: str = "boom",
    status: int | None = None,
    method: str | None = None,
    path: str | None = None,
    details: str = "",
    line_no: int = 1,
) -> LogEvent:
    event = LogEvent(
        source="test.log",
        line_no=line_no,
        raw=message,
        message=message,
        service=service,
        timestamp=at(t) if t is not None else None,
        level=level,
        http_status=status,
        http_method=method,
        http_path=path,
    )
    for line in details.splitlines():
        event.add_detail(line)
    return event
