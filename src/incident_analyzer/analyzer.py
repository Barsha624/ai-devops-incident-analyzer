from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from incident_analyzer.config import AnalyzerConfig
from incident_analyzer.detection import Finding, detect
from incident_analyzer.exceptions import MalformedLogError
from incident_analyzer.incidents import Incident, group_findings
from incident_analyzer.models import LogEvent
from incident_analyzer.reader import ParseStats, parse_file, parse_lines
from incident_analyzer.severity import SeverityRules, assess, attach_spikes
from incident_analyzer.spikes import SpikePeriod, detect_spikes

logger = logging.getLogger(__name__)

Source = tuple[ParseStats, Iterable[LogEvent]]
"""A parse-statistics holder plus the (lazy) event stream that fills it in."""

HIGH_MALFORMED_RATIO = 0.5


@dataclass
class AnalysisResult:
    stats: list[ParseStats]
    findings_total: int
    findings_by_kind: Counter[str]
    incidents: list[Incident]
    spikes: list[SpikePeriod]
    below_threshold_groups: int
    below_threshold_findings: int
    log_start: datetime | None
    log_end: datetime | None
    services: list[str]
    warnings: list[str] = field(default_factory=list)

    @property
    def events_parsed(self) -> int:
        return sum(s.events_parsed for s in self.stats)

    @property
    def malformed_lines(self) -> int:
        return sum(s.malformed_lines for s in self.stats)


def file_source(path: str | Path, default_service: str | None = None) -> Source:
    stats = ParseStats(source=str(path))
    return stats, parse_file(path, default_service=default_service, stats=stats)


def lines_source(lines: Iterable[str], name: str, default_service: str = "unknown") -> Source:
    stats = ParseStats(source=name)
    return stats, parse_lines(lines, name, default_service=default_service, stats=stats)


def analyze(
    sources: Iterable[Source], config: AnalyzerConfig, *, strict: bool = False
) -> AnalysisResult:
    """Run the full deterministic analysis. Never calls any AI service."""
    settings = config.analysis
    findings: list[Finding] = []
    by_kind: Counter[str] = Counter()
    services: set[str] = set()
    stats_list: list[ParseStats] = []
    findings_total = 0

    for stats, events in sources:
        stats_list.append(stats)
        for event in events:
            services.add(event.service)
            finding = detect(event)
            if finding is None:
                continue
            findings_total += 1
            by_kind[finding.kind.value] += 1
            if len(findings) < settings.max_findings:
                findings.append(finding)

    warnings = _collect_warnings(stats_list, findings, findings_total, settings.max_findings)

    if strict and any(s.malformed_lines for s in stats_list):
        detail = ", ".join(
            f"{s.source}: {s.malformed_lines}" for s in stats_list if s.malformed_lines
        )
        raise MalformedLogError(f"malformed lines found in strict mode ({detail})")

    starts = [s.first_timestamp for s in stats_list if s.first_timestamp is not None]
    ends = [s.last_timestamp for s in stats_list if s.last_timestamp is not None]
    log_start = min(starts) if starts else None
    log_end = max(ends) if ends else None

    spikes = detect_spikes(
        findings,
        log_start=log_start,
        log_end=log_end,
        window_seconds=settings.spike_window_seconds,
        factor=settings.spike_factor,
        min_count=settings.spike_min_count,
    )
    grouping = group_findings(
        findings,
        gap_seconds=settings.gap_seconds,
        min_events=settings.min_events,
        related_slack_seconds=settings.related_slack_seconds,
    )
    attach_spikes(grouping.incidents, spikes)

    rules = SeverityRules(critical_services=frozenset(settings.critical_services))
    for incident in grouping.incidents:
        assess(incident, log_end=log_end, gap_seconds=settings.gap_seconds, rules=rules)

    result = AnalysisResult(
        stats=stats_list,
        findings_total=findings_total,
        findings_by_kind=by_kind,
        incidents=grouping.incidents,
        spikes=spikes,
        below_threshold_groups=grouping.below_threshold_groups,
        below_threshold_findings=grouping.below_threshold_findings,
        log_start=log_start,
        log_end=log_end,
        services=sorted(services),
        warnings=warnings,
    )
    logger.info(
        "analysis_complete",
        extra={
            "event": "analysis_complete",
            "events_parsed": result.events_parsed,
            "malformed_lines": result.malformed_lines,
            "findings": findings_total,
            "incidents": len(result.incidents),
            "spikes": len(spikes),
        },
    )
    return result


def _collect_warnings(
    stats_list: list[ParseStats], findings: list[Finding], findings_total: int, max_findings: int
) -> list[str]:
    warnings: list[str] = []
    for stats in stats_list:
        if stats.events_parsed == 0:
            warnings.append(f"{stats.source}: no log events could be parsed")
        elif stats.malformed_ratio > HIGH_MALFORMED_RATIO:
            warnings.append(
                f"{stats.source}: {stats.malformed_ratio:.0%} of lines were not understood; "
                "the file may use an unsupported format (see docs/log-formats.md)"
            )
    undated = sum(1 for f in findings if f.timestamp is None)
    if undated:
        warnings.append(
            f"{undated} finding(s) have no parseable timestamp; they are excluded from "
            "time-based grouping and spike detection"
        )
    if findings_total > max_findings:
        warnings.append(
            f"findings capped at {max_findings} (saw {findings_total}); "
            "increase analysis.max_findings or narrow the input"
        )
    return warnings
