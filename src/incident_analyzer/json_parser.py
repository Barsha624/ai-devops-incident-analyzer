"""Parse one JSON log record (a dict) into a ``LogEvent``."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from incident_analyzer.models import LogEvent, parse_level
from incident_analyzer.timestamps import parse_timestamp

MAX_MESSAGE_CHARS = 2000
MAX_RAW_CHARS = 1000

# Field-name candidates, in priority order. Real-world loggers disagree on names, so we accept
# the common ones instead of forcing a single schema.
TIMESTAMP_KEYS = ("timestamp", "@timestamp", "time", "ts", "datetime", "date", "asctime")
LEVEL_KEYS = ("level", "severity", "levelname", "log_level", "loglevel")
SERVICE_KEYS = ("service", "service_name", "app", "application", "component", "logger", "name")
MESSAGE_KEYS = ("message", "msg", "error", "exception", "event", "text")
DETAIL_KEYS = ("stack", "stack_trace", "stacktrace", "traceback", "exc_info")
STATUS_KEYS = ("status", "status_code", "http_status", "statusCode")
METHOD_KEYS = ("method", "http_method", "request_method")
PATH_KEYS = ("path", "url", "route", "uri", "request_path")


def _first(record: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict | list):
        return json.dumps(value, default=str, separators=(",", ":"))
    return str(value)


def _as_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
    else:
        return None
    return number if 100 <= number <= 599 else None


def parse_json_record(
    record: Mapping[str, Any],
    *,
    source: str,
    line_no: int,
    raw: str,
    default_service: str,
) -> LogEvent | None:
    """Convert a decoded JSON object to a ``LogEvent``.

    Returns None when the object has none of the fields we understand (timestamp, level, message
    or HTTP status). That is reported as a malformed line instead of becoming an empty event.
    """
    timestamp = parse_timestamp(_first(record, TIMESTAMP_KEYS))
    level = parse_level(_first(record, LEVEL_KEYS))
    message_value = _first(record, MESSAGE_KEYS)
    status = _as_status(_first(record, STATUS_KEYS))
    method_value = _first(record, METHOD_KEYS)
    path_value = _first(record, PATH_KEYS)

    if timestamp is None and level is None and message_value is None and status is None:
        return None

    method = _as_text(method_value).upper() if method_value is not None else None
    path = _as_text(path_value) if path_value is not None else None

    if message_value is not None:
        message = _as_text(message_value)
    elif status is not None:
        message = " ".join(part for part in (method, path, f"-> {status}") if part)
    else:
        message = "(no message)"

    service_value = _first(record, SERVICE_KEYS)
    service = _as_text(service_value) if service_value is not None else default_service

    event = LogEvent(
        source=source,
        line_no=line_no,
        raw=raw[:MAX_RAW_CHARS],
        message=message[:MAX_MESSAGE_CHARS],
        service=service,
        timestamp=timestamp,
        level=level,
        http_status=status,
        http_method=method,
        http_path=path,
    )

    detail_value = _first(record, DETAIL_KEYS)
    if detail_value is not None:
        for line in _as_text(detail_value).splitlines():
            if line.strip():
                event.add_detail(line)
    return event
