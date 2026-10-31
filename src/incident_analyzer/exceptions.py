"""Exception hierarchy.

Every error this tool raises on purpose derives from ``IncidentAnalyzerError`` so the CLI can
catch one base class, print a clean message and exit with a meaningful status code instead of
showing a stack trace to the user. Unexpected bugs are NOT caught this way: they should crash
loudly so they get fixed.
"""

from __future__ import annotations


class IncidentAnalyzerError(Exception):
    """Base class for all expected, user-facing errors."""


class LogReadError(IncidentAnalyzerError):
    """A log file or stream could not be opened or read."""


class MalformedLogError(IncidentAnalyzerError):
    """Raised only in ``--strict`` mode when malformed lines are found."""


class ConfigError(IncidentAnalyzerError):
    """Configuration file or option is invalid."""


class SourceError(IncidentAnalyzerError):
    """A remote log source (for example CloudWatch) could not be queried."""


class AIError(IncidentAnalyzerError):
    """Base class for problems in the optional AI layer."""


class AIConsentError(AIError):
    """An external AI provider was requested without explicit opt-in."""


class AIProviderError(AIError):
    """The AI provider failed (network, authentication, server error)."""


class AIRateLimitError(AIProviderError):
    """The AI provider asked us to slow down."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class AIResponseError(AIError):
    """The model answered, but not with usable, schema-valid output."""
