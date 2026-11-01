from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from incident_analyzer.models import Level, LogEvent
from incident_analyzer.signatures import normalize_message, normalize_path


class FindingKind(StrEnum):
    HTTP_5XX = "http_5xx"
    TIMEOUT = "timeout"
    EXCEPTION = "exception"
    ERROR_LOG = "error_log"


RULE_HTTP_5XX = "R-HTTP-5XX"
RULE_TIMEOUT = "R-TIMEOUT"
RULE_EXCEPTION = "R-EXCEPTION"
RULE_ERROR_LEVEL = "R-ERROR-LEVEL"

# Highest first.
KIND_PRIORITY = (
    (RULE_HTTP_5XX, FindingKind.HTTP_5XX),
    (RULE_TIMEOUT, FindingKind.TIMEOUT),
    (RULE_EXCEPTION, FindingKind.EXCEPTION),
    (RULE_ERROR_LEVEL, FindingKind.ERROR_LOG),
)

_TIMEOUT_RE = re.compile(
    r"\btime[ds]?[ -]?out\b"  # timeout, timed out, time-out, times out
    r"|\b\w*timeout\w*\b"  # ReadTimeout, TimeoutError, timeouts
    r"|deadline exceeded|ETIMEDOUT",
    re.IGNORECASE,
)
_EXCEPTION_CLASS_RE = re.compile(r"\b((?:[A-Za-z_]\w*\.)*[A-Z][A-Za-z0-9_]*(?:Error|Exception))\b")
_TRACE_MARKER_RE = re.compile(
    r"Traceback \(most recent call last\)|^\s*at \S+\(.*\)|^Caused by:", re.MULTILINE
)


@dataclass(slots=True)
class Finding:
    """An event that matched at least one detection rule."""

    event: LogEvent
    kind: FindingKind
    signature: str
    rules: tuple[str, ...]
    exception_class: str | None = None

    @property
    def service(self) -> str:
        return self.event.service

    @property
    def timestamp(self) -> datetime | None:
        return self.event.timestamp


def _level_at_least(event: LogEvent, level: Level) -> bool:
    return event.level is not None and event.level >= level


def is_http_5xx(event: LogEvent) -> bool:
    """R-HTTP-5XX: the event carries an HTTP status between 500 and 599."""
    return event.http_status is not None and 500 <= event.http_status <= 599


def is_timeout(event: LogEvent) -> bool:
    """R-TIMEOUT: timeout wording at WARN or above, or HTTP 408/504.

    The level condition avoids flagging harmless INFO/DEBUG lines such as ``timeout=30s``.
    """
    if event.http_status in (408, 504):
        return True
    if not _level_at_least(event, Level.WARN):
        return False
    return _TIMEOUT_RE.search(f"{event.message} {event.detail_tail}") is not None


def find_exception_class(event: LogEvent) -> str | None:
    """Best-effort exception class name from the message, then the trace (last line first)."""
    candidates = [event.message, event.detail_tail, *reversed(event.details.splitlines())]
    for text in candidates:
        match = _EXCEPTION_CLASS_RE.search(text)
        if match:
            return match.group(1)
    return None


def is_exception(event: LogEvent) -> tuple[bool, str | None]:
    """R-EXCEPTION: ERROR+ with an exception class name, or any WARN+ with a stack trace."""
    has_trace = _TRACE_MARKER_RE.search(event.details) is not None or bool(
        _TRACE_MARKER_RE.search(event.message)
    )
    exception_class = find_exception_class(event)
    if _level_at_least(event, Level.ERROR) and (exception_class or has_trace):
        return True, exception_class or "UnknownException"
    if _level_at_least(event, Level.WARN) and has_trace:
        return True, exception_class or "UnknownException"
    return False, None


def is_error_level(event: LogEvent) -> bool:
    """R-ERROR-LEVEL: the event is logged at ERROR or CRITICAL."""
    return _level_at_least(event, Level.ERROR)


def _signature(event: LogEvent, kind: FindingKind, exception_class: str | None) -> str:
    if kind is FindingKind.HTTP_5XX:
        if event.http_path:
            method = f"{event.http_method} " if event.http_method else ""
            return f"HTTP {event.http_status} {method}{normalize_path(event.http_path)}"
        return f"HTTP {event.http_status}: {normalize_message(event.message, 80)}"
    if kind is FindingKind.EXCEPTION and exception_class:
        return exception_class
    return normalize_message(event.message)


def detect(event: LogEvent) -> Finding | None:
    """Run all rules on one event; return the highest-priority finding or None."""
    matched: list[str] = []
    exception_class: str | None = None

    if is_http_5xx(event):
        matched.append(RULE_HTTP_5XX)
    if is_timeout(event):
        matched.append(RULE_TIMEOUT)
    is_exc, exception_class = is_exception(event)
    if is_exc:
        matched.append(RULE_EXCEPTION)
    if is_error_level(event):
        matched.append(RULE_ERROR_LEVEL)

    if not matched:
        return None

    kind = next(kind for rule_id, kind in KIND_PRIORITY if rule_id in matched)
    return Finding(
        event=event,
        kind=kind,
        signature=_signature(event, kind, exception_class),
        rules=tuple(matched),
        exception_class=exception_class,
    )
