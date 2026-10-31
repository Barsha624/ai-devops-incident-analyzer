"""Command-line interface.

Exit codes:
    0  success
    1  analysis succeeded but ``--fail-on`` threshold was reached (useful as a CI gate)
    2  usage, configuration or input error
    130  interrupted (Ctrl+C)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from incident_analyzer import __version__
from incident_analyzer.analyzer import (
    AnalysisResult,
    Source,
    analyze,
    file_source,
    lines_source,
)
from incident_analyzer.config import AnalyzerConfig, load_config
from incident_analyzer.exceptions import ConfigError, IncidentAnalyzerError, LogReadError
from incident_analyzer.incidents import Severity
from incident_analyzer.logging_setup import configure_logging
from incident_analyzer.report import build_report, render_terminal, write_json

logger = logging.getLogger("incident_analyzer.cli")

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

LOG_SUFFIXES = {".log", ".json", ".jsonl", ".ndjson", ".txt", ".gz"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="incident-analyzer",
        description="Analyse application logs and produce evidence-based incident reports.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="analyse log files and report incidents")
    analyze_p.add_argument(
        "paths", nargs="+", metavar="PATH", help="log files, directories, or '-' for stdin"
    )
    analyze_p.add_argument("--config", help="path to a TOML config file")
    analyze_p.add_argument(
        "--format", choices=("terminal", "json", "both"), default="terminal", help="output format"
    )
    analyze_p.add_argument("-o", "--output", help="write the JSON report to this file")
    analyze_p.add_argument("--default-service", help="service name for records that name none")
    analyze_p.add_argument("--strict", action="store_true", help="fail if any line is malformed")
    analyze_p.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="exit with status 1 if an incident of this severity or higher is found",
    )
    analyze_p.add_argument("--no-color", action="store_true", help="disable coloured output")

    tuning = analyze_p.add_argument_group("analysis tuning (override the config file)")
    tuning.add_argument("--gap-seconds", type=int)
    tuning.add_argument("--min-events", type=int)
    tuning.add_argument("--spike-window-seconds", type=int)
    tuning.add_argument("--spike-factor", type=float)
    tuning.add_argument("--spike-min-count", type=int)
    tuning.add_argument("--max-evidence", type=int)

    diag = analyze_p.add_argument_group("diagnostics (the tool's own logging, written to stderr)")
    diag.add_argument("--log-level", help="DEBUG, INFO, WARNING, ERROR or CRITICAL")
    diag.add_argument("--log-format", choices=("text", "json"))
    return parser


def _apply_overrides(config: AnalyzerConfig, args: argparse.Namespace) -> None:
    for name in (
        "gap_seconds",
        "min_events",
        "spike_window_seconds",
        "spike_factor",
        "spike_min_count",
        "max_evidence",
    ):
        value = getattr(args, name, None)
        if value is not None:
            setattr(config.analysis, name, value)
    if getattr(args, "log_level", None):
        config.logging.level = args.log_level
    if getattr(args, "log_format", None):
        config.logging.format = args.log_format
    config.validate()


def _expand_paths(paths: Sequence[str]) -> list[str]:
    """Expand directories into their log files; keep '-' (stdin) and files as they are."""
    expanded: list[str] = []
    for raw in paths:
        if raw == "-":
            expanded.append(raw)
            continue
        path = Path(raw)
        if not path.exists():
            raise LogReadError(f"path does not exist: {raw}")
        if path.is_dir():
            found = sorted(
                p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in LOG_SUFFIXES
            )
            if not found:
                logger.warning("directory contains no log files", extra={"path": raw})
            expanded.extend(str(p) for p in found)
        else:
            expanded.append(str(path))
    return expanded


def _build_sources(paths: Sequence[str], default_service: str | None) -> list[Source]:
    sources: list[Source] = []
    for path in _expand_paths(paths):
        if path == "-":
            sources.append(lines_source(sys.stdin, "<stdin>", default_service or "stdin"))
        else:
            sources.append(file_source(path, default_service))
    if not sources:
        raise LogReadError("no log files found in the given paths")
    return sources


def _use_color(args: argparse.Namespace) -> bool:
    return not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _cmd_analyze(args: argparse.Namespace, config: AnalyzerConfig) -> int:
    if args.format == "both" and not args.output:
        raise ConfigError("--format both needs --output to say where the JSON report goes")

    sources = _build_sources(args.paths, args.default_service)
    result: AnalysisResult = analyze(sources, config, strict=args.strict)
    report = build_report(result, config)

    if args.output:
        write_json(report, args.output)
        logger.info("report_written", extra={"event": "report_written", "path": args.output})

    if args.format in ("terminal", "both"):
        sys.stdout.write(render_terminal(report, color=_use_color(args)))
    if args.format == "json":
        if args.output:
            sys.stderr.write(f"report written to {args.output}\n")
        else:
            sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(i.severity >= threshold for i in result.incidents):
            return EXIT_THRESHOLD
    return EXIT_OK


def _report_error(exc: Exception, log_format: str) -> None:
    """Show an expected error once: as a structured log line, or as a plain message."""
    if log_format == "json":
        logger.error("command_failed", extra={"event": "command_failed", "error": str(exc)})
    else:
        sys.stderr.write(f"error: {exc}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    log_format = "text"
    try:
        config = load_config(args.config)
        _apply_overrides(config, args)
        log_format = config.logging.format
        configure_logging(config.logging.level, log_format)
        if args.command == "analyze":
            return _cmd_analyze(args, config)
        parser.error(f"unknown command {args.command!r}")  # pragma: no cover
    except IncidentAnalyzerError as exc:
        _report_error(exc, log_format)
        return EXIT_ERROR
    except BrokenPipeError:  # e.g. `... | head`; not an error worth a traceback
        return EXIT_OK
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return EXIT_INTERRUPTED
    return EXIT_OK  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
