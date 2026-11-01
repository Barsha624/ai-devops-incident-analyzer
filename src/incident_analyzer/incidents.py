from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from functools import cached_property

from incident_analyzer.detection import Finding
from incident_analyzer.models import Level
from incident_analyzer.spikes import SpikePeriod

_FAR_FUTURE = datetime.max.replace(tzinfo=UTC)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Incident:
    service: str
    findings: list[Finding]
    id: str = ""
    severity: Severity = Severity.LOW
    severity_score: int = 0
    severity_reasons: list[str] = field(default_factory=list)
    spikes: list[SpikePeriod] = field(default_factory=list)
    related_incident_ids: list[str] = field(default_factory=list)

    @cached_property
    def timestamps(self) -> list[datetime]:
        return [f.timestamp for f in self.findings if f.timestamp is not None]

    @property
    def first_seen(self) -> datetime | None:
        return min(self.timestamps) if self.timestamps else None

    @property
    def last_seen(self) -> datetime | None:
        return max(self.timestamps) if self.timestamps else None

    @property
    def duration_seconds(self) -> float | None:
        if self.first_seen is None or self.last_seen is None:
            return None
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def count(self) -> int:
        return len(self.findings)

    @cached_property
    def kind_counts(self) -> Counter[str]:
        return Counter(f.kind.value for f in self.findings)

    @cached_property
    def signature_counts(self) -> Counter[str]:
        return Counter(f.signature for f in self.findings)

    @cached_property
    def rules_triggered(self) -> list[str]:
        return sorted({rule for f in self.findings for rule in f.rules})

    @property
    def has_critical_level(self) -> bool:
        return any(f.event.level == Level.CRITICAL for f in self.findings)

    @property
    def title(self) -> str:
        signature, count = self.signature_counts.most_common(1)[0]
        others = len(self.signature_counts) - 1
        suffix = f" (+{others} other signature{'s' if others != 1 else ''})" if others else ""
        return f"{self.service}: {signature} x{count}{suffix}"


@dataclass
class GroupingResult:
    incidents: list[Incident]
    below_threshold_groups: int
    below_threshold_findings: int


def _sort_key(finding: Finding) -> tuple[datetime, str, int]:
    return (finding.timestamp or _FAR_FUTURE, finding.event.source, finding.event.line_no)


def _split_by_gap(findings: list[Finding], gap_seconds: float) -> list[list[Finding]]:
    groups: list[list[Finding]] = []
    for finding in sorted(findings, key=_sort_key):
        if groups:
            previous = groups[-1][-1].timestamp
            current = finding.timestamp
            assert previous is not None and current is not None
            if (current - previous).total_seconds() <= gap_seconds:
                groups[-1].append(finding)
                continue
        groups.append([finding])
    return groups


def group_findings(
    findings: Iterable[Finding],
    *,
    gap_seconds: int,
    min_events: int,
    related_slack_seconds: int = 60,
) -> GroupingResult:
    """Cluster findings into incidents and number them ``INC-001``, ``INC-002``, ..."""
    by_service: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_service[finding.service].append(finding)

    groups: list[tuple[str, list[Finding]]] = []
    for service in sorted(by_service):
        dated = [f for f in by_service[service] if f.timestamp is not None]
        undated = [f for f in by_service[service] if f.timestamp is None]
        groups.extend((service, group) for group in _split_by_gap(dated, gap_seconds))
        if undated:
            groups.append((service, sorted(undated, key=_sort_key)))

    incidents: list[Incident] = []
    below_groups = 0
    below_findings = 0
    for service, group in groups:
        incident = Incident(service=service, findings=group)
        if incident.count >= min_events or incident.has_critical_level:
            incidents.append(incident)
        else:
            below_groups += 1
            below_findings += incident.count

    incidents.sort(key=lambda i: (i.first_seen or _FAR_FUTURE, i.service))
    for number, incident in enumerate(incidents, start=1):
        incident.id = f"INC-{number:03d}"

    _link_related(incidents, related_slack_seconds)
    return GroupingResult(incidents, below_groups, below_findings)


def _link_related(incidents: list[Incident], slack_seconds: int) -> None:
    dated = [i for i in incidents if i.first_seen is not None and i.last_seen is not None]
    for index, a in enumerate(dated):
        for b in dated[index + 1 :]:
            if a.service == b.service:
                continue
            assert a.first_seen and a.last_seen and b.first_seen and b.last_seen
            gap_a = (b.first_seen - a.last_seen).total_seconds()
            gap_b = (a.first_seen - b.last_seen).total_seconds()
            if gap_a <= slack_seconds and gap_b <= slack_seconds:
                a.related_incident_ids.append(b.id)
                b.related_incident_ids.append(a.id)
