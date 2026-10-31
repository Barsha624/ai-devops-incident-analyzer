"""Build the machine-readable report and render the terminal summary.

The JSON report is the single source of truth: the terminal view is rendered *from the report
dict*, so the two can never disagree. Report schema: docs/report-schema.md.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from incident_analyzer import __version__
from incident_analyzer.analyzer import AnalysisResult
from incident_analyzer.config import AnalyzerConfig
from incident_analyzer.detection import Finding
from incident_analyzer.exceptions import ReportWriteError
from incident_analyzer.incidents import Incident, Severity
from incident_analyzer.spikes import SpikePeriod
from incident_analyzer.timestamps import format_timestamp

SCHEMA_VERSION = "1.0"
MAX_EXCERPT_CHARS = 400
TOP_SIGNATURES = 5


def select_evidence(incident: Incident, limit: int) -> list[Finding]:
    """Pick representative findings: one example per signature (most common first) + the last.

    Deterministic and bounded, so reports stay small and reproducible.
    """
    firsts: dict[str, Finding] = {}
    for finding in incident.findings:
        firsts.setdefault(finding.signature, finding)

    ordered = [firsts[sig] for sig, _ in incident.signature_counts.most_common() if sig in firsts]
    chosen = ordered[: max(limit - 1, 1)]
    last = incident.findings[-1]
    if last not in chosen and len(chosen) < limit:
        chosen.append(last)
    chosen.sort(key=lambda f: (f.timestamp or datetime.max.replace(tzinfo=UTC), f.event.line_no))
    return chosen[:limit]


def _evidence_dict(incident_id: str, number: int, finding: Finding) -> dict[str, Any]:
    event = finding.event
    excerpt = event.raw
    if event.detail_tail:
        excerpt = f"{excerpt} | {event.detail_tail}"
    return {
        "evidence_id": f"{incident_id}-E{number}",
        "source": event.source,
        "line": event.line_no,
        "timestamp": format_timestamp(event.timestamp),
        "level": event.level.name if event.level is not None else None,
        "kind": finding.kind.value,
        "rules": list(finding.rules),
        "signature": finding.signature,
        "excerpt": excerpt[:MAX_EXCERPT_CHARS],
    }


def _spike_dict(spike: SpikePeriod) -> dict[str, Any]:
    return {
        "service": spike.service,
        "start": format_timestamp(spike.start),
        "end": format_timestamp(spike.end),
        "peak_findings_per_window": spike.peak_count,
        "total_findings": spike.total_count,
        "window_seconds": spike.window_seconds,
        "baseline_per_window": spike.baseline,
        "threshold_per_window": spike.threshold,
    }


def incident_to_dict(incident: Incident, max_evidence: int) -> dict[str, Any]:
    evidence = select_evidence(incident, max_evidence)
    return {
        "id": incident.id,
        "title": incident.title,
        "service": incident.service,
        "severity": incident.severity.label,
        "severity_score": incident.severity_score,
        "severity_reasons": list(incident.severity_reasons),
        "first_seen": format_timestamp(incident.first_seen),
        "last_seen": format_timestamp(incident.last_seen),
        "duration_seconds": incident.duration_seconds,
        "finding_count": incident.count,
        "kinds": dict(incident.kind_counts.most_common()),
        "rules_triggered": incident.rules_triggered,
        "top_signatures": [
            {"signature": sig, "count": count}
            for sig, count in incident.signature_counts.most_common(TOP_SIGNATURES)
        ],
        "spikes": [_spike_dict(s) for s in incident.spikes],
        "possibly_related_incidents": list(incident.related_incident_ids),
        "evidence": [_evidence_dict(incident.id, n, f) for n, f in enumerate(evidence, start=1)],
    }


def build_report(
    result: AnalysisResult,
    config: AnalyzerConfig,
    *,
    generated_at: datetime | None = None,
    ai: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the JSON-serialisable report."""
    generated = generated_at or datetime.now(UTC)
    severity_counts = {s.label: 0 for s in Severity}
    for incident in result.incidents:
        severity_counts[incident.severity.label] += 1
    highest = max((i.severity for i in result.incidents), default=None)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "ai-devops-incident-analyzer", "version": __version__},
        "generated_at": format_timestamp(generated),
        "settings": config.analysis_settings(),
        "inputs": [
            {
                "source": s.source,
                "lines_read": s.lines_read,
                "events_parsed": s.events_parsed,
                "malformed_lines": s.malformed_lines,
                "malformed_samples": [
                    {"line": m.line_no, "reason": m.reason, "snippet": m.snippet}
                    for m in s.malformed_samples
                ],
                "level_counts": dict(s.level_counts),
            }
            for s in result.stats
        ],
        "summary": {
            "events_parsed": result.events_parsed,
            "malformed_lines": result.malformed_lines,
            "findings": result.findings_total,
            "findings_by_kind": dict(result.findings_by_kind.most_common()),
            "incidents": len(result.incidents),
            "incidents_by_severity": severity_counts,
            "highest_severity": highest.label if highest is not None else None,
            "time_range": {
                "start": format_timestamp(result.log_start),
                "end": format_timestamp(result.log_end),
            },
            "services": result.services,
            "below_threshold": {
                "groups": result.below_threshold_groups,
                "findings": result.below_threshold_findings,
            },
        },
        "incidents": [incident_to_dict(i, config.analysis.max_evidence) for i in result.incidents],
        "spikes": [_spike_dict(s) for s in result.spikes],
        "warnings": list(result.warnings),
        "ai": ai,
    }


def write_json(report: dict[str, Any], path: str | Path) -> None:
    """Write the report as pretty JSON, creating parent directories if needed."""
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReportWriteError(f"cannot write report to {target}: {exc}") from exc


# --------------------------------------------------------------------------- terminal rendering

_COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;32m",
}
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _short(ts: str | None) -> str:
    return f"{ts[:19]}Z" if ts else "n/a"


def _minutes(seconds: float | None) -> str:
    if seconds is None:
        return "n/a"
    return f"{seconds / 60:.1f} min" if seconds >= 60 else f"{seconds:.0f} s"


def render_terminal(report: dict[str, Any], *, color: bool = False, max_evidence: int = 3) -> str:
    """Human-readable summary rendered from the report dict."""

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    summary = report["summary"]
    lines: list[str] = []
    lines.append(paint(f"Incident analysis  (tool v{report['tool']['version']})", _BOLD))
    time_range = summary["time_range"]
    lines.append(
        f"Inputs: {len(report['inputs'])} source(s) | events parsed: {summary['events_parsed']} "
        f"| malformed lines: {summary['malformed_lines']}"
    )
    lines.append(f"Time range: {_short(time_range['start'])} -> {_short(time_range['end'])}")
    kinds = ", ".join(f"{k}={v}" for k, v in summary["findings_by_kind"].items()) or "none"
    lines.append(f"Findings: {summary['findings']} ({kinds})")
    by_sev = (
        ", ".join(f"{k}={v}" for k, v in summary["incidents_by_severity"].items() if v) or "none"
    )
    lines.append(f"Incidents: {summary['incidents']} ({by_sev})")
    below = summary["below_threshold"]
    if below["findings"]:
        lines.append(
            f"Below reporting threshold: {below['findings']} finding(s) in {below['groups']} "
            "small group(s), not reported as incidents"
        )

    for warning in report["warnings"]:
        lines.append(paint(f"WARNING: {warning}", _COLORS["medium"]))

    if not report["incidents"]:
        lines.append("")
        lines.append("No incidents detected.")

    for incident in report["incidents"]:
        lines.append("")
        badge = paint(f" {incident['severity'].upper()} ", _COLORS[incident["severity"]])
        lines.append(f"[{badge}] {incident['id']}  {incident['title']}")
        lines.append(
            f"  window   : {_short(incident['first_seen'])} -> {_short(incident['last_seen'])} "
            f"({_minutes(incident['duration_seconds'])}), {incident['finding_count']} findings"
        )
        lines.append("  kinds    : " + ", ".join(f"{k}={v}" for k, v in incident["kinds"].items()))
        lines.append(f"  score    : {incident['severity_score']}  (why:)")
        for reason in incident["severity_reasons"]:
            lines.append(f"             {reason}")
        for spike in incident["spikes"]:
            peak = spike["peak_findings_per_window"]
            baseline = spike["baseline_per_window"]
            lines.append(
                f"  spike    : {_short(spike['start'])} -> {_short(spike['end'])}, "
                f"peak {peak}/window vs baseline {baseline:g}"
            )
        if incident["possibly_related_incidents"]:
            lines.append(
                "  related  : "
                + ", ".join(incident["possibly_related_incidents"])
                + " (overlap in time only; not proof of causation)"
            )
        lines.append("  evidence :")
        for item in incident["evidence"][:max_evidence]:
            where = f"{Path(item['source']).name}:{item['line']}"
            lines.append(paint(f"    - {where} [{_short(item['timestamp'])}]", _DIM))
            excerpt = item["excerpt"]
            lines.append(f"      {excerpt[:160]}{'...' if len(excerpt) > 160 else ''}")
        extra = len(incident["evidence"]) - max_evidence
        if extra > 0:
            lines.append(f"    ... and {extra} more in the JSON report")

    ai = report.get("ai")
    if ai:
        lines.append("")
        lines.append(
            paint("AI explanation (generated text; unverified; does not change severity)", _BOLD)
        )
        lines.append(f"  status: {ai['status']}  provider: {ai.get('provider')}")
        if ai.get("error"):
            lines.append(f"  note: {ai['error']}")
        for item in ai.get("incidents", []):
            lines.append(f"  {item['incident_id']}: {item['summary']}")
            for hypothesis in item["hypotheses"]:
                lines.append(
                    f"    hypothesis ({hypothesis['confidence']}): {hypothesis['statement']}"
                )
            for step in item["investigation_steps"]:
                lines.append(f"    next step: {step}")
    return "\n".join(lines) + "\n"
