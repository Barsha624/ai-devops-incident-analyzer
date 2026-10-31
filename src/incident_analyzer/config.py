"""Configuration: sensible defaults, optional TOML file, strict validation.

Design choices worth knowing:

* Unknown keys are an **error**, not silently ignored, so a typo such as ``gap_second`` cannot
  quietly leave you running with defaults.
* API keys are never read from the config file. They come from environment variables only, so
  a config file can be committed without leaking a secret.
"""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from incident_analyzer.exceptions import ConfigError

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
VALID_LOG_FORMATS = ("text", "json")
VALID_AI_PROVIDERS = ("offline", "anthropic", "openai-compatible")


@dataclass
class AnalysisConfig:
    gap_seconds: int = 300
    """Findings of one service further apart than this start a new incident."""
    min_events: int = 3
    """Minimum findings in a cluster to report it (a CRITICAL-level log always qualifies)."""
    spike_window_seconds: int = 60
    spike_factor: float = 3.0
    spike_min_count: int = 10
    max_evidence: int = 5
    max_findings: int = 200_000
    """Safety cap on stored findings so a runaway log cannot exhaust memory."""
    related_slack_seconds: int = 60
    critical_services: tuple[str, ...] = ()
    """Services whose incidents get +1 severity point (your own business-critical services)."""


@dataclass
class LoggingConfig:
    level: str = "WARNING"
    format: str = "text"


@dataclass
class AIConfig:
    enabled: bool = False
    provider: str = "offline"
    model: str = "claude-haiku-5-5"
    base_url: str = ""
    max_incidents: int = 5
    max_evidence_per_incident: int = 5
    max_tokens: int = 1200
    timeout_seconds: float = 30.0
    max_retries: int = 2
    allow_external: bool = False


@dataclass
class AnalyzerConfig:
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    ai: AIConfig = field(default_factory=AIConfig)

    def validate(self) -> None:
        a, lg, ai = self.analysis, self.logging, self.ai
        _require(a.gap_seconds > 0, "analysis.gap_seconds must be > 0")
        _require(a.min_events >= 1, "analysis.min_events must be >= 1")
        _require(a.spike_window_seconds > 0, "analysis.spike_window_seconds must be > 0")
        _require(a.spike_factor > 1.0, "analysis.spike_factor must be > 1")
        _require(a.spike_min_count >= 1, "analysis.spike_min_count must be >= 1")
        _require(a.max_evidence >= 1, "analysis.max_evidence must be >= 1")
        _require(a.max_findings >= 1, "analysis.max_findings must be >= 1")
        _require(a.related_slack_seconds >= 0, "analysis.related_slack_seconds must be >= 0")
        _require(
            lg.level.upper() in VALID_LOG_LEVELS, f"logging.level must be one of {VALID_LOG_LEVELS}"
        )
        _require(
            lg.format in VALID_LOG_FORMATS, f"logging.format must be one of {VALID_LOG_FORMATS}"
        )
        _require(
            ai.provider in VALID_AI_PROVIDERS, f"ai.provider must be one of {VALID_AI_PROVIDERS}"
        )
        _require(ai.max_incidents >= 1, "ai.max_incidents must be >= 1")
        _require(ai.max_evidence_per_incident >= 1, "ai.max_evidence_per_incident must be >= 1")
        _require(ai.max_tokens >= 100, "ai.max_tokens must be >= 100")
        _require(ai.timeout_seconds > 0, "ai.timeout_seconds must be > 0")
        _require(ai.max_retries >= 0, "ai.max_retries must be >= 0")

    def analysis_settings(self) -> dict[str, Any]:
        """The analysis settings, as written into the report so results are reproducible."""
        data = asdict(self.analysis)
        data["critical_services"] = list(self.analysis.critical_services)
        return data


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _coerce(value: Any, current: Any, name: str) -> Any:
    """Check ``value`` has the same type as the default ``current`` and return it."""
    if isinstance(current, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{name} must be true or false")
        return value
    if isinstance(current, int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{name} must be an integer")
        return value
    if isinstance(current, float):
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(f"{name} must be a number")
        return float(value)
    if isinstance(current, tuple):
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ConfigError(f"{name} must be a list of strings")
        return tuple(value)
    if isinstance(current, str):
        if not isinstance(value, str):
            raise ConfigError(f"{name} must be a string")
        return value
    raise ConfigError(f"{name}: unsupported option type")  # pragma: no cover


def _apply_section(target: Any, data: Any, section: str) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"[{section}] must be a table")
    allowed = {f.name for f in fields(target)}
    for key, value in data.items():
        if key not in allowed:
            raise ConfigError(
                f"unknown option {key!r} in [{section}]; valid options: {sorted(allowed)}"
            )
        setattr(target, key, _coerce(value, getattr(target, key), f"{section}.{key}"))


def load_config(path: str | Path | None = None) -> AnalyzerConfig:
    """Load defaults, then overlay a TOML file if one is given."""
    config = AnalyzerConfig()
    if path is not None:
        file_path = Path(path)
        try:
            raw = file_path.read_bytes()
        except FileNotFoundError as exc:
            raise ConfigError(f"config file not found: {file_path}") from exc
        except OSError as exc:
            raise ConfigError(f"cannot read config file {file_path}: {exc}") from exc
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"invalid TOML in {file_path}: {exc}") from exc

        for section, values in data.items():
            if section not in ("analysis", "logging", "ai"):
                raise ConfigError(
                    f"unknown section [{section}]; valid sections: analysis, logging, ai"
                )
            _apply_section(getattr(config, section), values, section)

    config.validate()
    return config
