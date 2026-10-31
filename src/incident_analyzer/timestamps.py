"""Timestamp parsing.

All timestamps are normalised to timezone-aware UTC datetimes. Naive timestamps (no offset in
the log) are assumed to already be UTC; this assumption is documented in docs/limitations.md.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime

# Apache / nginx "common log format" timestamp, e.g. 31/Oct/2026:09:30:00 +0000
_ACCESS_LOG_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _from_epoch(number: float) -> datetime | None:
    """Convert seconds / milliseconds / microseconds / nanoseconds since epoch."""
    magnitude = abs(number)
    if magnitude >= 1e17:
        number /= 1e9
    elif magnitude >= 1e14:
        number /= 1e6
    elif magnitude >= 1e11:
        number /= 1e3
    try:
        return datetime.fromtimestamp(number, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def parse_timestamp(value: object) -> datetime | None:
    """Parse a timestamp from a JSON value or a text fragment.

    Returns None (never raises) when the value is not a recognisable timestamp, so a single bad
    field cannot abort an analysis run.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return _from_epoch(float(value))
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    parsed: datetime | None = None
    with contextlib.suppress(ValueError):  # not a plain number: fall through to text formats
        parsed = _from_epoch(float(text))
    if parsed is not None:
        return parsed

    try:
        parsed = datetime.strptime(text, _ACCESS_LOG_FORMAT)
    except ValueError:
        parsed = None

    if parsed is None:
        # Python's own logging uses a comma before milliseconds: 2026-10-31 09:30:00,123
        try:
            parsed = datetime.fromisoformat(text.replace(",", "."))
        except ValueError:
            return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime | None) -> str | None:
    """ISO-8601 in UTC with a trailing Z, or None."""
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
