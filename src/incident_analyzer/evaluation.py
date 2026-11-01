from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from incident_analyzer.analyzer import analyze, file_source
from incident_analyzer.config import AnalyzerConfig
from incident_analyzer.exceptions import ConfigError
from incident_analyzer.timestamps import parse_timestamp


@dataclass
class Expected:
    name: str
    service: str
    start: datetime
    end: datetime


@dataclass
class EvaluationResult:
    expected: int
    detected: int
    matched_expected: int
    matched_detected: int
    missed: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float | None:
        return self.matched_expected / self.expected if self.expected else None

    @property
    def precision(self) -> float | None:
        return self.matched_detected / self.detected if self.detected else None


def load_labels(path: str | Path) -> tuple[list[Path], list[Expected]]:
    labels_path = Path(path)
    try:
        data: Any = json.loads(labels_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read labels file {labels_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"labels file {labels_path} is not valid JSON: {exc}") from exc
    try:
        logs = [labels_path.parent / entry for entry in data["logs"]]
        expected = []
        for entry in data["expected_incidents"]:
            start, end = parse_timestamp(entry["start"]), parse_timestamp(entry["end"])
            if start is None or end is None or end < start:
                raise ConfigError(f"bad time range for expected incident {entry.get('name')!r}")
            expected.append(
                Expected(entry.get("name", entry["service"]), entry["service"], start, end)
            )
    except (KeyError, TypeError) as exc:
        raise ConfigError(
            f'labels file needs "logs" and "expected_incidents" lists ({exc!r} is missing or wrong)'
        ) from exc
    return logs, expected


def evaluate(labels_path: str | Path, config: AnalyzerConfig | None = None) -> EvaluationResult:
    logs, expected = load_labels(labels_path)
    result = analyze([file_source(log) for log in logs], config or AnalyzerConfig())

    def overlaps(
        exp: Expected, service: str, first: datetime | None, last: datetime | None
    ) -> bool:
        return (
            exp.service == service
            and first is not None
            and last is not None
            and first <= exp.end
            and last >= exp.start
        )

    matched_expected = [
        e
        for e in expected
        if any(overlaps(e, i.service, i.first_seen, i.last_seen) for i in result.incidents)
    ]
    matched_detected = [
        i
        for i in result.incidents
        if any(overlaps(e, i.service, i.first_seen, i.last_seen) for e in expected)
    ]
    return EvaluationResult(
        expected=len(expected),
        detected=len(result.incidents),
        matched_expected=len(matched_expected),
        matched_detected=len(matched_detected),
        missed=[e.name for e in expected if e not in matched_expected],
        unexpected=[i.title for i in result.incidents if i not in matched_detected],
    )


def render(result: EvaluationResult) -> str:
    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.0%}"

    lines = [
        f"expected incidents : {result.expected}",
        f"detected incidents : {result.detected}",
        f"recall             : {pct(result.recall)} ({result.matched_expected}/{result.expected})",
        f"precision          : {pct(result.precision)} "
        f"({result.matched_detected}/{result.detected})",
    ]
    lines += [f"  missed     : {name}" for name in result.missed]
    lines += [f"  unexpected : {title}" for title in result.unexpected]
    lines.append("Only as meaningful as the labelled data. See docs/evaluation.md.")
    return "\n".join(lines) + "\n"
