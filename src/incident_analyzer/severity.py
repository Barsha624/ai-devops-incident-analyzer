from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from incident_analyzer.detection import FindingKind
from incident_analyzer.incidents import Incident, Severity
from incident_analyzer.spikes import SpikePeriod

BASE_POINTS = {
    FindingKind.HTTP_5XX: 2,
    FindingKind.TIMEOUT: 2,
    FindingKind.EXCEPTION: 2,
    FindingKind.ERROR_LOG: 1,
}


@dataclass(frozen=True)
class SeverityRules:
    volume_steps: tuple[tuple[int, int], ...] = ((100, 3), (20, 2), (5, 1))
    """(minimum findings, points) pairs, checked from the largest down."""
    long_duration_seconds: int = 300
    critical_level_points: int = 2
    medium_at: int = 3
    high_at: int = 5
    critical_at: int = 7
    critical_services: frozenset[str] = field(default_factory=frozenset)


def attach_spikes(incidents: Iterable[Incident], spikes: Iterable[SpikePeriod]) -> None:
    """Link each spike to incidents of the same service whose time range overlaps it."""
    spike_list = list(spikes)
    for incident in incidents:
        first, last = incident.first_seen, incident.last_seen
        if first is None or last is None:
            continue
        incident.spikes = [
            s
            for s in spike_list
            if s.service == incident.service and s.start <= last and s.end > first
        ]


def score_to_severity(score: int, rules: SeverityRules) -> Severity:
    if score >= rules.critical_at:
        return Severity.CRITICAL
    if score >= rules.high_at:
        return Severity.HIGH
    if score >= rules.medium_at:
        return Severity.MEDIUM
    return Severity.LOW


def assess(
    incident: Incident,
    *,
    log_end: datetime | None,
    gap_seconds: int,
    rules: SeverityRules | None = None,
) -> None:
    """Compute ``severity``, ``severity_score`` and ``severity_reasons`` for one incident."""
    rules = rules or SeverityRules()
    score = 0
    reasons: list[str] = []

    base_kind = max(incident.kind_counts, key=lambda k: BASE_POINTS[FindingKind(k)])
    base = BASE_POINTS[FindingKind(base_kind)]
    score += base
    reasons.append(f"+{base} base: most serious finding kind is {base_kind}")

    for minimum, points in rules.volume_steps:
        if incident.count >= minimum:
            score += points
            reasons.append(f"+{points} volume: {incident.count} findings (>= {minimum})")
            break

    duration = incident.duration_seconds
    if duration is not None and duration >= rules.long_duration_seconds:
        score += 1
        limit = rules.long_duration_seconds / 60
        reasons.append(f"+1 duration: lasted {duration / 60:.1f} min (>= {limit:g} min)")

    if incident.spikes:
        peak = max(s.peak_count for s in incident.spikes)
        score += 1
        reasons.append(
            f"+1 spike: error spike overlaps this incident (peak {peak} findings/window)"
        )

    if incident.has_critical_level:
        score += rules.critical_level_points
        reasons.append(f"+{rules.critical_level_points} critical: CRITICAL/FATAL log line present")

    if len(incident.kind_counts) >= 2:
        score += 1
        reasons.append(f"+1 variety: {len(incident.kind_counts)} different finding kinds")

    if incident.service in rules.critical_services:
        score += 1
        reasons.append("+1 service: service is listed in critical_services")

    last_seen = incident.last_seen
    if (
        log_end is not None
        and last_seen is not None
        and last_seen >= log_end - timedelta(seconds=gap_seconds)
    ):
        score += 1
        reasons.append("+1 ongoing: findings continue until the end of the analysed logs")

    incident.severity_score = score
    incident.severity = score_to_severity(score, rules)
    incident.severity_reasons = reasons
