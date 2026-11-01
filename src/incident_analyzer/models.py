from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

MAX_DETAIL_LINES = 40
MAX_DETAIL_CHARS = 4000
MAX_TAIL_CHARS = 500


class Level(IntEnum):
    """Normalised log severity. IntEnum so we can write ``level >= Level.ERROR``."""

    TRACE = 0
    DEBUG = 10
    INFO = 20
    WARN = 30
    ERROR = 40
    CRITICAL = 50


_LEVEL_ALIASES: dict[str, Level] = {
    "trace": Level.TRACE,
    "debug": Level.DEBUG,
    "info": Level.INFO,
    "information": Level.INFO,
    "notice": Level.INFO,
    "warn": Level.WARN,
    "warning": Level.WARN,
    "error": Level.ERROR,
    "err": Level.ERROR,
    "severe": Level.ERROR,
    "critical": Level.CRITICAL,
    "crit": Level.CRITICAL,
    "fatal": Level.CRITICAL,
    "alert": Level.CRITICAL,
    "emergency": Level.CRITICAL,
    "emerg": Level.CRITICAL,
}


def parse_level(value: object) -> Level | None:
    """Map a free-form level string to ``Level``; return None if it is not recognised.

    Numeric levels are deliberately NOT supported: pino uses 50 for "error" while Python's
    logging uses 50 for "critical", so guessing would silently produce wrong results.
    """
    if not isinstance(value, str):
        return None
    return _LEVEL_ALIASES.get(value.strip().lower())


@dataclass(slots=True)
class LogEvent:
    """One logical log record (a log line plus any stack-trace continuation lines)."""

    source: str
    line_no: int
    raw: str
    message: str
    service: str = "unknown"
    timestamp: datetime | None = None
    level: Level | None = None
    http_status: int | None = None
    http_method: str | None = None
    http_path: str | None = None
    details: str = ""
    detail_tail: str = ""
    _detail_lines: int = field(default=0, repr=False)

    def add_detail(self, line: str) -> None:
        """Attach a continuation line (for example a traceback frame).

        Memory is bounded: only the first ``MAX_DETAIL_LINES`` lines are kept in full, but the
        most recent line is always remembered in ``detail_tail`` because for Python tracebacks
        the final line is the one that names the exception.
        """
        stripped = line.strip()
        self.detail_tail = stripped[:MAX_TAIL_CHARS]
        if self._detail_lines >= MAX_DETAIL_LINES or len(self.details) >= MAX_DETAIL_CHARS:
            return
        self.details = f"{self.details}\n{stripped}" if self.details else stripped
        self._detail_lines += 1
