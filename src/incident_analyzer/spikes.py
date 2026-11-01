from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from incident_analyzer.detection import Finding


@dataclass(frozen=True, slots=True)
class SpikePeriod:
    service: str
    start: datetime
    end: datetime
    peak_count: int
    total_count: int
    baseline: float
    threshold: float
    window_seconds: int


def median_with_zeros(counts: Iterable[int], total_windows: int) -> float:
    """Median of ``total_windows`` values where all windows not listed in ``counts`` are zero."""
    non_zero = [c for c in counts if c > 0]
    zeros = max(total_windows - len(non_zero), 0)
    if not non_zero:
        return 0.0
    if zeros > len(non_zero):  # more than half the windows are zero
        return 0.0
    return float(statistics.median([0] * zeros + non_zero))


def detect_spikes(
    findings: Iterable[Finding],
    *,
    log_start: datetime | None,
    log_end: datetime | None,
    window_seconds: int = 60,
    factor: float = 3.0,
    min_count: int = 10,
) -> list[SpikePeriod]:
    """Return spike periods per service. Findings without timestamps are ignored."""
    if log_start is None or log_end is None:
        return []

    start_idx = int(log_start.timestamp() // window_seconds)
    end_idx = int(log_end.timestamp() // window_seconds)
    total_windows = end_idx - start_idx + 1

    per_service: dict[str, Counter[int]] = defaultdict(Counter)
    for finding in findings:
        if finding.timestamp is not None:
            per_service[finding.service][int(finding.timestamp.timestamp() // window_seconds)] += 1

    periods: list[SpikePeriod] = []
    for service in sorted(per_service):
        window_counts = per_service[service]
        baseline = median_with_zeros(window_counts.values(), total_windows)
        threshold = max(float(min_count), factor * max(baseline, 1.0))
        spiking = sorted(idx for idx, count in window_counts.items() if count >= threshold)

        group: list[int] = []
        for idx in [*spiking, None]:
            if group and (idx is None or idx != group[-1] + 1):
                counts = [window_counts[i] for i in group]
                periods.append(
                    SpikePeriod(
                        service=service,
                        start=datetime.fromtimestamp(group[0] * window_seconds, tz=UTC),
                        end=datetime.fromtimestamp(group[-1] * window_seconds, tz=UTC)
                        + timedelta(seconds=window_seconds),
                        peak_count=max(counts),
                        total_count=sum(counts),
                        baseline=baseline,
                        threshold=threshold,
                        window_seconds=window_seconds,
                    )
                )
                group = []
            if idx is not None:
                group.append(idx)

    periods.sort(key=lambda p: (p.start, p.service))
    return periods
