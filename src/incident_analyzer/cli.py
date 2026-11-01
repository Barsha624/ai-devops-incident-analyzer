from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from incident_analyzer.redaction import redact_report
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
        "paths", nargs="*", metavar="PATH", help="log files, directories, or '-' for stdin"
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
    analyze_p.add_argument(
        "--redact", action="store_true", help="redact secrets/PII in report excerpts"
    )
    analyze_p.add_argument("--metrics-file", help="also write Prometheus metrics to this file")

    cw = analyze_p.add_argument_group(
        "optional source: AWS CloudWatch Logs (needs the [aws] extra)"
    )
    cw.add_argument("--cloudwatch-group", help="log group name, e.g. /aws/ecs/checkout")
    cw.add_argument("--since", default="1h", help="30m, 2h, 1d or an ISO timestamp (default 1h)")
    cw.add_argument("--filter-pattern", help="CloudWatch filter pattern, e.g. ERROR")
    cw.add_argument("--max-events", type=int, default=100_000)
    cw.add_argument("--region")
    cw.add_argument("--profile")

    ai = analyze_p.add_argument_group("optional AI explanation (off by default)")
    ai.add_argument("--ai", action="store_true", help="add an AI explanation section")
    ai.add_argument(
        "--ai-dry-run", action="store_true", help="show exactly what would be sent; sends nothing"
    )
    ai.add_argument("--ai-provider", choices=("offline", "anthropic", "openai-compatible"))
    ai.add_argument("--ai-model")
    ai.add_argument("--ai-base-url")
    ai.add_argument(
        "--allow-external-ai",
        action="store_true",
        help="consent to sending redacted data off-machine",
    )

    tuning = analyze_p.add_argument_group("analysis tuning (override the config file)")
    tuning.add_argument("--gap-seconds", type=int)
    tuning.add_argument("--min-events", type=int)
    tuning.add_argument("--spike-window-seconds", type=int)
    tuning.add_argument("--spike-factor", type=float)
    tuning.add_argument("--spike-min-count", type=int)
    tuning.add_argument("--max-evidence", type=int)

    diag_help = "diagnostics (the tool's own logging, written to stderr)"
    serve_p = sub.add_parser("serve", help="re-analyse logs periodically and expose /metrics")
    serve_p.add_argument("paths", nargs="+", metavar="PATH")
    serve_p.add_argument("--config", help="path to a TOML config file")
    serve_p.add_argument("--default-service")
    serve_p.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 in Docker)")
    serve_p.add_argument("--port", type=int, default=9108)
    serve_p.add_argument("--interval", type=float, default=30.0, help="seconds between analyses")

    eval_p = sub.add_parser("evaluate", help="measure precision/recall against a labels file")
    eval_p.add_argument("labels", help="labels JSON (see docs/evaluation.md)")
    eval_p.add_argument("--config", help="path to a TOML config file")

    for command in (analyze_p, serve_p, eval_p):
        diag = command.add_argument_group(diag_help)
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
    for name in ("ai_provider", "ai_model", "ai_base_url"):
        value = getattr(args, name, None)
        if value:
            setattr(config.ai, name.removeprefix("ai_"), value)
    if getattr(args, "allow_external_ai", False):
        config.ai.allow_external = True
    if getattr(args, "ai", False) or getattr(args, "ai_dry_run", False):
        config.ai.enabled = True
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


def _cloudwatch_source(args: argparse.Namespace) -> tuple[Source, list[str]]:
    """Fetch from CloudWatch Logs. Imported lazily so the core never needs boto3."""
    from incident_analyzer.cloudwatch import fetch_records, parse_since, records_to_source

    now = datetime.now(UTC)
    records, truncated = fetch_records(
        args.cloudwatch_group,
        start=parse_since(args.since, now),
        end=now,
        filter_pattern=args.filter_pattern,
        region=args.region,
        profile=args.profile,
        max_events=args.max_events,
    )
    warnings = []
    if truncated:
        warnings.append(
            f"CloudWatch fetch stopped at {args.max_events} events; "
            "narrow --since or --filter-pattern for complete results"
        )
    return records_to_source(records, args.cloudwatch_group), warnings


def _cmd_analyze(args: argparse.Namespace, config: AnalyzerConfig) -> int:
    if args.format == "both" and not args.output:
        raise ConfigError("--format both needs --output to say where the JSON report goes")
    if not args.paths and not args.cloudwatch_group:
        raise ConfigError("give at least one PATH, or --cloudwatch-group NAME")

    started = time.perf_counter()
    sources = _build_sources(args.paths, args.default_service) if args.paths else []
    extra_warnings: list[str] = []
    if args.cloudwatch_group:
        source, extra_warnings = _cloudwatch_source(args)
        sources.append(source)
    result: AnalysisResult = analyze(sources, config, strict=args.strict)
    result.warnings.extend(extra_warnings)
    report = build_report(result, config)
    if args.redact:
        redact_report(report)
    if config.ai.enabled:
        from incident_analyzer.ai import explain  # lazy: the core never imports the AI layer

        report["ai"] = explain(report, config.ai, dry_run=args.ai_dry_run)
    if args.metrics_file:
        from incident_analyzer.metrics import render_metrics, write_metrics_file

        write_metrics_file(
            args.metrics_file,
            render_metrics(report, analysis_seconds=time.perf_counter() - started),
        )

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


def _cmd_serve(args: argparse.Namespace, config: AnalyzerConfig) -> int:
    from incident_analyzer.metrics import MetricsExporter, create_server

    if args.interval <= 0:
        raise ConfigError("--interval must be > 0")
    if not 1 <= args.port <= 65535:
        raise ConfigError("--port must be between 1 and 65535")
    _expand_paths(args.paths)  # fail fast on a bad path, before listening

    def analyze_once() -> dict[str, Any]:
        sources = _build_sources(args.paths, args.default_service)
        return build_report(analyze(sources, config), config)

    exporter = MetricsExporter(analyze_once, args.interval)
    exporter.refresh(raise_errors=True)  # first run must work, or we do not start
    try:
        server = create_server(exporter, args.host, args.port)
    except OSError as exc:
        raise ConfigError(f"cannot listen on {args.host}:{args.port}: {exc}") from exc

    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)  # docker stop
    exporter.start()
    logger.warning("serving metrics on http://%s:%s/metrics", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        exporter.stop()
        server.server_close()
    return EXIT_OK


def _cmd_evaluate(args: argparse.Namespace, config: AnalyzerConfig) -> int:
    from incident_analyzer.evaluation import evaluate, render

    result = evaluate(args.labels, config)
    sys.stdout.write(render(result))
    return EXIT_THRESHOLD if (result.missed or result.unexpected) else EXIT_OK


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
        commands = {"analyze": _cmd_analyze, "serve": _cmd_serve, "evaluate": _cmd_evaluate}
        if args.command in commands:
            return commands[args.command](args, config)
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
