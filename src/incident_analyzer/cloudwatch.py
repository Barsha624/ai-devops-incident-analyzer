from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from incident_analyzer.analyzer import Source
from incident_analyzer.exceptions import ConfigError, SourceError
from incident_analyzer.models import LogEvent
from incident_analyzer.reader import ParseStats, parse_lines

logger = logging.getLogger(__name__)

DEFAULT_MAX_EVENTS = 100_000
PAGE_LIMIT = 10_000  # API maximum per call

_SINCE = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass(frozen=True)
class CloudWatchRecord:
    timestamp: datetime
    message: str
    stream: str = ""


def parse_since(value: str, now: datetime | None = None) -> datetime:
    """``30m`` / ``2h`` / ``1d`` (relative to now) or an ISO-8601 timestamp -> aware datetime."""
    now = now or datetime.now(UTC)
    text = value.strip()
    match = _SINCE.match(text)
    if match:
        seconds = int(match.group(1)) * _UNITS[match.group(2)]
        return now - timedelta(seconds=seconds)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ConfigError(
            f"invalid --since value {value!r}: use a duration such as 30m, 2h, 1d "
            "or an ISO-8601 timestamp"
        ) from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _aws_error_types() -> tuple[type[Exception], ...]:
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return ()
    return (BotoCoreError, ClientError)


def _make_client(region: str | None, profile: str | None) -> Any:
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise SourceError(
            'boto3 is not installed. Install the AWS extra: pip install ".[aws]"'
        ) from None
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        return session.client(
            "logs", config=Config(retries={"max_attempts": 5, "mode": "standard"})
        )
    except _aws_error_types() as exc:
        raise SourceError(f"cannot create the AWS client: {exc}") from exc


def _describe(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    code = ""
    if isinstance(response, dict):
        code = str(response.get("Error", {}).get("Code", ""))
    if code == "ResourceNotFoundException":
        return "log group not found (check the name and region)"
    if code in ("AccessDeniedException", "UnauthorizedOperation"):
        return "access denied: the credentials need logs:FilterLogEvents on this log group"
    if code in ("ThrottlingException", "Throttling"):
        return "throttled by CloudWatch Logs after several retries; narrow --since or retry later"
    if code in ("ExpiredTokenException", "UnrecognizedClientException"):
        return "AWS credentials are expired or invalid"
    return str(exc)


def _to_record(event: dict[str, Any]) -> CloudWatchRecord:
    return CloudWatchRecord(
        timestamp=datetime.fromtimestamp(int(event["timestamp"]) / 1000, tz=UTC),
        message=str(event.get("message", "")),
        stream=str(event.get("logStreamName", "")),
    )


def fetch_records(
    log_group: str,
    *,
    start: datetime,
    end: datetime,
    filter_pattern: str | None = None,
    region: str | None = None,
    profile: str | None = None,
    max_events: int = DEFAULT_MAX_EVENTS,
    client: Any = None,
) -> tuple[list[CloudWatchRecord], bool]:
    """Fetch events for the time range. Returns ``(records, truncated)``."""
    if client is None:
        client = _make_client(region, profile)
    kwargs: dict[str, Any] = {
        "logGroupName": log_group,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
        "limit": min(PAGE_LIMIT, max_events),
    }
    if filter_pattern:
        kwargs["filterPattern"] = filter_pattern

    records: list[CloudWatchRecord] = []
    token: str | None = None
    truncated = False
    try:
        while True:
            page = client.filter_log_events(**kwargs, **({"nextToken": token} if token else {}))
            for event in page.get("events", []):
                if len(records) >= max_events:
                    truncated = True
                    break
                records.append(_to_record(event))
            token = page.get("nextToken")
            if truncated or not token:
                break
            if len(records) >= max_events:
                truncated = True
                break
    except _aws_error_types() as exc:
        raise SourceError(f"CloudWatch Logs request failed: {_describe(exc)}") from exc
    logger.info(
        "cloudwatch_fetched",
        extra={"event": "cloudwatch_fetched", "log_group": log_group, "records": len(records)},
    )
    return records, truncated


def records_to_source(
    records: list[CloudWatchRecord], log_group: str, default_service: str | None = None
) -> Source:
    """Parse CloudWatch messages with the normal parsers.

    Each message is split into lines and all lines are parsed as one stream, so a stack trace
    that arrives inside one CloudWatch event stays attached to its log line. Lines that carry
    no timestamp of their own fall back to the CloudWatch ingestion time.
    """
    service = default_service or log_group.rstrip("/").rsplit("/", 1)[-1] or "unknown"
    stats = ParseStats(source=f"cloudwatch:{log_group}")
    lines: list[str] = []
    stamps: list[datetime] = []  # ingestion time of the record each line came from
    for record in records:
        for line in record.message.splitlines() or [""]:
            lines.append(line)
            stamps.append(record.timestamp)

    def events() -> Iterator[LogEvent]:
        for event in parse_lines(lines, stats.source, default_service=service, stats=stats):
            if event.timestamp is None and 0 < event.line_no <= len(stamps):
                event.timestamp = stamps[event.line_no - 1]
            yield event

    return stats, events()
