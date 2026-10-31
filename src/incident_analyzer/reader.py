"""Read log files and streams into ``LogEvent`` objects.

The key design rule: **one bad line must never abort the analysis**. Lines we cannot parse are
counted and sampled in ``ParseStats`` so the report can say how much input was understood.
"""

from __future__ import annotations

import gzip
import json
import logging
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import IO

from incident_analyzer.exceptions import LogReadError
from incident_analyzer.json_parser import parse_json_record
from incident_analyzer.models import Level, LogEvent
from incident_analyzer.text_parser import is_continuation, parse_text_line

logger = logging.getLogger(__name__)

MAX_MALFORMED_SAMPLES = 5
MAX_JSON_ARRAY_BYTES = 100 * 1024 * 1024


@dataclass(slots=True)
class MalformedSample:
    line_no: int
    reason: str
    snippet: str


@dataclass(slots=True)
class ParseStats:
    """Counters collected while reading one source."""

    source: str
    lines_read: int = 0
    events_parsed: int = 0
    malformed_lines: int = 0
    malformed_samples: list[MalformedSample] = field(default_factory=list)
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    level_counts: Counter[str] = field(default_factory=Counter)

    def record_event(self, event: LogEvent) -> None:
        self.events_parsed += 1
        self.level_counts[event.level.name if event.level is not None else "UNKNOWN"] += 1
        ts = event.timestamp
        if ts is not None:
            if self.first_timestamp is None or ts < self.first_timestamp:
                self.first_timestamp = ts
            if self.last_timestamp is None or ts > self.last_timestamp:
                self.last_timestamp = ts

    def record_malformed(self, line_no: int, reason: str, raw: str) -> None:
        self.malformed_lines += 1
        if len(self.malformed_samples) < MAX_MALFORMED_SAMPLES:
            self.malformed_samples.append(MalformedSample(line_no, reason, raw[:120]))

    @property
    def malformed_ratio(self) -> float:
        total = self.events_parsed + self.malformed_lines
        return self.malformed_lines / total if total else 0.0


def parse_lines(
    lines: Iterable[str],
    source: str,
    *,
    default_service: str = "unknown",
    stats: ParseStats | None = None,
) -> Iterator[LogEvent]:
    """Yield events from an iterable of lines (a file, stdin, or CloudWatch messages)."""
    stats = stats if stats is not None else ParseStats(source=source)
    current: LogEvent | None = None  # text record that may still receive continuation lines

    def emit(event: LogEvent) -> LogEvent:
        stats.record_event(event)
        return event

    for line_no, raw_line in enumerate(lines, start=1):
        stats.lines_read += 1
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue

        if line.startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                stats.record_malformed(line_no, f"invalid JSON: {exc.msg}", line)
                continue
            if not isinstance(record, dict):
                stats.record_malformed(line_no, "JSON value is not an object", line)
                continue
            event = parse_json_record(
                record, source=source, line_no=line_no, raw=line, default_service=default_service
            )
            if event is None:
                stats.record_malformed(line_no, "JSON object has no recognisable log fields", line)
                continue
            if current is not None:
                yield emit(current)
                current = None
            yield emit(event)
            continue

        event = parse_text_line(
            line, source=source, line_no=line_no, default_service=default_service
        )
        if event is not None:
            if current is not None:
                yield emit(current)
            current = event
            continue

        if current is not None and is_continuation(line):
            current.add_detail(line)
            continue

        stats.record_malformed(line_no, "line does not match any supported format", line)

    if current is not None:
        yield emit(current)


def parse_json_array(
    text: str, source: str, *, default_service: str, stats: ParseStats
) -> Iterator[LogEvent]:
    """Yield events from a file that holds one JSON array of log objects."""
    try:
        records = json.loads(text)
    except json.JSONDecodeError as exc:
        stats.lines_read += 1
        stats.record_malformed(exc.lineno, f"invalid JSON array: {exc.msg}", "")
        return
    if not isinstance(records, list):
        stats.lines_read += 1
        stats.record_malformed(1, "top-level JSON value is not an array", "")
        return
    for index, record in enumerate(records, start=1):
        stats.lines_read += 1
        if not isinstance(record, dict):
            stats.record_malformed(index, "array item is not an object", str(record))
            continue
        event = parse_json_record(
            record,
            source=source,
            line_no=index,
            raw=json.dumps(record, default=str),
            default_service=default_service,
        )
        if event is None:
            stats.record_malformed(index, "JSON object has no recognisable log fields", "")
            continue
        stats.record_event(event)
        yield event


def service_name_from_path(path: Path) -> str:
    """``payments-api.log.gz`` -> ``payments-api``. Used when a record names no service."""
    name = path.name
    if name.endswith(".gz"):
        name = name[:-3]
    return Path(name).stem or "unknown"


def _open_text(path: Path) -> IO[str]:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_file(
    path: str | Path,
    *,
    default_service: str | None = None,
    stats: ParseStats | None = None,
) -> Iterator[LogEvent]:
    """Yield events from a log file (JSON Lines, JSON array, plain text, optionally ``.gz``)."""
    file_path = Path(path)
    service = default_service or service_name_from_path(file_path)
    stats = stats if stats is not None else ParseStats(source=str(file_path))

    try:
        handle = _open_text(file_path)
    except FileNotFoundError as exc:
        raise LogReadError(f"log file not found: {file_path}") from exc
    except IsADirectoryError as exc:
        raise LogReadError(f"expected a file but got a directory: {file_path}") from exc
    except PermissionError as exc:
        raise LogReadError(f"permission denied reading: {file_path}") from exc
    except OSError as exc:
        raise LogReadError(f"cannot open {file_path}: {exc}") from exc

    try:
        with handle:
            lines = iter(handle)
            buffered: list[str] = []
            for line in lines:
                buffered.append(line)
                if line.strip():
                    break

            first_content = buffered[-1].lstrip() if buffered else ""
            if first_content.startswith("["):
                if file_path.stat().st_size > MAX_JSON_ARRAY_BYTES and file_path.suffix != ".gz":
                    limit_mb = MAX_JSON_ARRAY_BYTES // (1024 * 1024)
                    raise LogReadError(
                        f"JSON array file is larger than {limit_mb} MB; "
                        "convert it to JSON Lines (one object per line)"
                    )
                text = "".join(chain(buffered, lines))
                yield from parse_json_array(
                    text, str(file_path), default_service=service, stats=stats
                )
            else:
                yield from parse_lines(
                    chain(buffered, lines), str(file_path), default_service=service, stats=stats
                )
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise LogReadError(f"error while reading {file_path}: {exc}") from exc

    logger.info(
        "file_parsed",
        extra={
            "event": "file_parsed",
            "source": str(file_path),
            "lines_read": stats.lines_read,
            "events_parsed": stats.events_parsed,
            "malformed_lines": stats.malformed_lines,
        },
    )


__all__ = [
    "Level",
    "MalformedSample",
    "ParseStats",
    "parse_file",
    "parse_json_array",
    "parse_lines",
    "service_name_from_path",
]
