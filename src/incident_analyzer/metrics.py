from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from incident_analyzer import __version__
from incident_analyzer.exceptions import IncidentAnalyzerError, ReportWriteError

logger = logging.getLogger(__name__)

PREFIX = "incident_analyzer"
SEVERITIES = ("low", "medium", "high", "critical")
KINDS = ("http_5xx", "timeout", "exception", "error_log")
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(labels: Mapping[str, str]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{_escape(str(v))}"' for k, v in labels.items()) + "}"


def _format_value(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")


class _Writer:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(
        self,
        name: str,
        kind: str,
        help_text: str,
        samples: list[tuple[Mapping[str, str], float]],
    ) -> None:
        full = f"{PREFIX}_{name}"
        self.lines.append(f"# HELP {full} {help_text}")
        self.lines.append(f"# TYPE {full} {kind}")
        for labels, value in samples:
            self.lines.append(f"{full}{_format_labels(labels)} {_format_value(value)}")


def render_metrics(
    report: dict[str, Any] | None,
    *,
    analysis_seconds: float | None = None,
    now: float | None = None,
    failures: int = 0,
) -> str:
    """Render Prometheus text exposition format from a report dict (or just info + failures)."""
    w = _Writer()
    w.family(
        "info", "gauge", "Build information (value is always 1).", [({"version": __version__}, 1)]
    )
    w.family(
        "analysis_failures_total",
        "counter",
        "Analyses that failed since the exporter started.",
        [({}, failures)],
    )
    if report is None:
        return "\n".join(w.lines) + "\n"

    summary = report["summary"]
    w.family(
        "last_analysis_timestamp_seconds",
        "gauge",
        "Unix time of the last successful analysis.",
        [({}, time.time() if now is None else now)],
    )
    if analysis_seconds is not None:
        w.family(
            "analysis_duration_seconds",
            "gauge",
            "Seconds the last analysis took.",
            [({}, analysis_seconds)],
        )
    w.family(
        "events_parsed",
        "gauge",
        "Log events parsed in the last analysis.",
        [({}, summary["events_parsed"])],
    )
    w.family(
        "malformed_lines",
        "gauge",
        "Lines that could not be parsed in the last analysis.",
        [({}, summary["malformed_lines"])],
    )
    by_kind = summary["findings_by_kind"]
    w.family(
        "findings",
        "gauge",
        "Findings by detection kind in the last analysis.",
        [({"kind": k}, by_kind.get(k, 0)) for k in KINDS],
    )
    by_sev = summary["incidents_by_severity"]
    w.family(
        "incidents",
        "gauge",
        "Incidents by severity in the last analysis.",
        [({"severity": s}, by_sev.get(s, 0)) for s in SEVERITIES],
    )
    highest = summary.get("highest_severity")
    rank = SEVERITIES.index(highest) + 1 if highest in SEVERITIES else 0
    w.family(
        "highest_severity",
        "gauge",
        "Highest incident severity (0 none, 1 low, 2 medium, 3 high, 4 critical).",
        [({}, rank)],
    )
    w.family(
        "error_spikes",
        "gauge",
        "Error spikes detected in the last analysis.",
        [({}, len(report.get("spikes", [])))],
    )
    return "\n".join(w.lines) + "\n"


def write_metrics_file(path: str | Path, text: str) -> None:
    """Write atomically (temp file + rename) so a collector never reads a half-written file."""
    target = Path(path)
    tmp = target.with_name(target.name + ".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, target)
    except OSError as exc:
        raise ReportWriteError(f"cannot write metrics file {target}: {exc}") from exc


class MetricsExporter:
    """Holds the latest report and refreshes it on an interval.

    If a refresh fails, the last good numbers keep being served and the failure counter
    goes up, so an alert on ``analysis_failures_total`` can fire without the dashboard going blank.
    """

    def __init__(self, analyze_once: Callable[[], dict[str, Any]], interval: float) -> None:
        self._analyze_once = analyze_once
        self.interval = interval
        self._lock = threading.Lock()
        self._report: dict[str, Any] | None = None
        self._seconds: float | None = None
        self._stamp: float | None = None
        self._failures = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def refresh(self, *, raise_errors: bool = False) -> bool:
        started = time.perf_counter()
        try:
            report = self._analyze_once()
        except Exception as exc:
            with self._lock:
                self._failures += 1
            if raise_errors:
                raise
            if isinstance(exc, IncidentAnalyzerError):
                logger.error("refresh_failed", extra={"event": "refresh_failed", "error": str(exc)})
            else:  # a bug, not an expected error: keep the exporter alive but record the traceback
                logger.exception("refresh_crashed", extra={"event": "refresh_crashed"})
            return False
        with self._lock:
            self._report = report
            self._seconds = time.perf_counter() - started
            self._stamp = time.time()
        return True

    @property
    def text(self) -> str:
        with self._lock:
            return render_metrics(
                self._report,
                analysis_seconds=self._seconds,
                now=self._stamp,
                failures=self._failures,
            )

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self.interval):
                self.refresh()

        self._thread = threading.Thread(target=loop, name="metrics-refresh", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def create_server(exporter: MetricsExporter, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - name fixed by http.server
            if self.path == "/metrics":
                body, ctype, code = exporter.text.encode(), CONTENT_TYPE, 200
            elif self.path == "/healthz":
                body, ctype, code = b"ok\n", "text/plain; charset=utf-8", 200
            else:
                body, ctype, code = b"not found\n", "text/plain; charset=utf-8", 404
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug("http: " + format, *args)

    return ThreadingHTTPServer((host, port), Handler)
