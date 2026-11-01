from __future__ import annotations

import re

from incident_analyzer.json_parser import MAX_MESSAGE_CHARS, MAX_RAW_CHARS
from incident_analyzer.models import Level, LogEvent, parse_level
from incident_analyzer.timestamps import parse_timestamp

_LEVELS = r"TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRITICAL|FATAL|SEVERE"
_TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"

_PYTHON_STYLE = re.compile(
    rf"^(?P<ts>{_TS})\s+-\s+(?P<svc>[\w.\-]+)\s+-\s+(?P<level>{_LEVELS})\s+-\s+(?P<msg>.*)$",
    re.IGNORECASE,
)
_STANDARD = re.compile(
    rf"^(?P<ts>{_TS})\s+\[?(?P<level>{_LEVELS})\]?\s+(?:\[(?P<svc>[^\]]+)\]\s*)?(?P<msg>.*)$",
    re.IGNORECASE,
)
_ACCESS_LOG = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)'
    r'[^"]*"\s+(?P<status>\d{3})\s+\S+'
)

_KV_SERVICE = re.compile(r"\b(?:service|svc)=([\w.\-]+)")
_HTTP_METHOD_PATH = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/\S*)")

# HTTP status extraction from free text. Each pattern needs an explicit "status"/"HTTP" cue so
# that phrases such as "query returned 500 rows" do not become fake 5xx errors.
_STATUS_PATTERNS = (
    re.compile(r"\b(?:status|status_code|http_status)\s*[=:]\s*\"?(?P<s>[1-5]\d{2})\b", re.I),
    re.compile(r"\bHTTP(?:/\d(?:\.\d)?\"?)?\s+(?P<s>[1-5]\d{2})\b", re.I),
    re.compile(r"\bstatus(?:\s+code)?\s+(?P<s>[1-5]\d{2})\b", re.I),
)

_CONTINUATION_START = re.compile(
    r"^(?:\s+\S|Traceback \(most recent call last\)|Caused by:|\.\.\. \d+ more"
    r"|[A-Za-z_][\w.]*(?:Error|Exception|Warning)(?::|$))"
)


def extract_http_status(message: str) -> int | None:
    """Find an HTTP status code in free text, or None."""
    for pattern in _STATUS_PATTERNS:
        match = pattern.search(message)
        if match:
            return int(match.group("s"))
    return None


def is_continuation(line: str) -> bool:
    """True for lines that belong to the previous record (stack-trace frames and so on)."""
    return bool(_CONTINUATION_START.match(line))


def _enrich_from_message(message: str) -> tuple[int | None, str | None, str | None]:
    status = extract_http_status(message)
    method_path = _HTTP_METHOD_PATH.search(message)
    if method_path:
        return status, method_path.group(1), method_path.group(2)
    return status, None, None


def parse_text_line(
    line: str, *, source: str, line_no: int, default_service: str
) -> LogEvent | None:
    """Parse one text line into a ``LogEvent``; return None if no known shape matches."""
    for pattern in (_PYTHON_STYLE, _STANDARD):
        match = pattern.match(line)
        if not match:
            continue
        message = match.group("msg").strip()
        service = match.group("svc")
        if not service:
            kv = _KV_SERVICE.search(message)
            service = kv.group(1) if kv else default_service
        status, method, path = _enrich_from_message(message)
        return LogEvent(
            source=source,
            line_no=line_no,
            raw=line[:MAX_RAW_CHARS],
            message=message[:MAX_MESSAGE_CHARS],
            service=service.strip() or default_service,
            timestamp=parse_timestamp(match.group("ts")),
            level=parse_level(match.group("level")),
            http_status=status,
            http_method=method,
            http_path=path,
        )

    access = _ACCESS_LOG.match(line)
    if access:
        status = int(access.group("status"))
        method = access.group("method")
        path = access.group("path")
        level = Level.ERROR if status >= 500 else Level.WARN if status >= 400 else Level.INFO
        return LogEvent(
            source=source,
            line_no=line_no,
            raw=line[:MAX_RAW_CHARS],
            message=f"{method} {path} -> {status}",
            service=default_service,
            timestamp=parse_timestamp(access.group("ts")),
            level=level,
            http_status=status if 100 <= status <= 599 else None,
            http_method=method,
            http_path=path,
        )
    return None
