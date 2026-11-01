from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

from incident_analyzer.config import AIConfig
from incident_analyzer.exceptions import AIProviderError, AIRateLimitError, ConfigError

logger = logging.getLogger(__name__)

ANTHROPIC_URL = "https://api.anthropic.com"
OPENAI_URL = "https://api.openai.com/v1"
ANTHROPIC_VERSION = "2023-06-01"
MAX_BACKOFF_SECONDS = 60.0
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

Urlopen = Callable[..., Any]


@dataclass(frozen=True)
class Completion:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str, *, max_tokens: int) -> Completion: ...


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return max(0.0, min(float(value), MAX_BACKOFF_SECONDS))
    except ValueError:
        return None


def _usage(data: dict[str, Any], in_key: str = "input_tokens", out_key: str = "output_tokens"):  # type: ignore[no-untyped-def]
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return None, None
    return usage.get(in_key), usage.get(out_key)


def _error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(exc.read().decode("utf-8", "replace"))
        error = body.get("error", {}) if isinstance(body, dict) else {}
        message = error.get("message") if isinstance(error, dict) else error
        return str(message)[:200] if message else ""
    except (ValueError, OSError, AttributeError):
        return ""


class HTTPClient:
    """POST JSON with bounded retries for rate limits, server errors and network failures."""

    def __init__(
        self,
        timeout: float,
        max_retries: int,
        sleep: Callable[[float], None] = time.sleep,
        urlopen: Urlopen = urllib.request.urlopen,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._sleep = sleep
        self._urlopen = urlopen

    def post_json(
        self, url: str, headers: Mapping[str, str], body: dict[str, Any]
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        for attempt in range(self._max_retries + 1):
            last = attempt == self._max_retries
            try:
                with self._urlopen(request, timeout=self._timeout) as response:
                    raw = response.read()
            except urllib.error.HTTPError as exc:
                detail = _error_detail(exc)
                retry_after = _parse_retry_after(
                    exc.headers.get("Retry-After") if exc.headers else None
                )
                retryable = exc.code == 429 or exc.code >= 500
                if retryable and not last:
                    delay = (
                        retry_after
                        if retry_after is not None
                        else min(2.0**attempt, MAX_BACKOFF_SECONDS)
                    )
                    self._backoff(attempt, delay)
                    continue
                if exc.code == 429:
                    raise AIRateLimitError(
                        f"rate limited by provider (HTTP 429) {detail}".strip(), retry_after
                    ) from None
                if exc.code >= 500:
                    raise AIProviderError(
                        f"provider error (HTTP {exc.code}) {detail}".strip()
                    ) from None
                raise AIProviderError(f"request rejected (HTTP {exc.code}): {detail}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if not last:
                    self._backoff(attempt, min(2.0**attempt, MAX_BACKOFF_SECONDS))
                    continue
                raise AIProviderError(f"network error talking to provider: {exc}") from exc
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise AIProviderError(
                    "provider returned a response that is not valid JSON"
                ) from None
            if not isinstance(data, dict):
                raise AIProviderError("provider returned an unexpected response shape")
            return data
        raise AIProviderError("request failed")  # pragma: no cover

    def _backoff(self, attempt: int, delay: float) -> None:
        logger.warning(
            "ai_retry", extra={"event": "ai_retry", "attempt": attempt + 1, "delay_seconds": delay}
        )
        self._sleep(delay)


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str | None, model: str, base_url: str, http: HTTPClient) -> None:
        if not api_key:
            raise AIProviderError("ANTHROPIC_API_KEY is not set in the environment")
        self._api_key = api_key
        self.model = model
        self._url = (base_url or ANTHROPIC_URL).rstrip("/") + "/v1/messages"
        self._http = http

    def __repr__(self) -> str:  # never reveal the key
        return f"AnthropicProvider(model={self.model!r})"

    def complete(self, system: str, user: str, *, max_tokens: int) -> Completion:
        data = self._http.post_json(
            self._url,
            {"x-api-key": self._api_key, "anthropic-version": ANTHROPIC_VERSION},
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        blocks = data.get("content")
        if not isinstance(blocks, list):
            raise AIProviderError("Anthropic response has no content blocks")
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        in_tok, out_tok = _usage(data)
        return Completion(text, in_tok, out_tok)


class OpenAICompatibleProvider:
    """Works with OpenAI and with local servers that copy its API (for example Ollama)."""

    name = "openai-compatible"

    def __init__(self, api_key: str | None, model: str, base_url: str, http: HTTPClient) -> None:
        self._base = (base_url or OPENAI_URL).rstrip("/")
        if not api_key and not is_local_url(self._base):
            raise AIProviderError("OPENAI_API_KEY is not set in the environment")
        self._api_key = api_key
        self.model = model
        self._http = http

    def __repr__(self) -> str:
        return f"OpenAICompatibleProvider(model={self.model!r})"

    def complete(self, system: str, user: str, *, max_tokens: int) -> Completion:
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        data = self._http.post_json(
            f"{self._base}/chat/completions",
            headers,
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        try:
            text = str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            raise AIProviderError("response has no choices[0].message.content") from None
        in_tok, out_tok = _usage(data, "prompt_tokens", "completion_tokens")
        return Completion(text, in_tok, out_tok)


def is_local_url(url: str) -> bool:
    return (urlparse(url).hostname or "") in LOCAL_HOSTS


def is_external(config: AIConfig) -> bool:
    """True when using this configuration would send data off this machine."""
    if config.provider == "offline":
        return False
    if config.provider == "openai-compatible":
        return not is_local_url(config.base_url or OPENAI_URL)
    return True


def create_provider(config: AIConfig, environ: Mapping[str, str]) -> Provider:
    """Build the provider named in the config. API keys come from the environment only."""
    if config.provider == "offline":
        from incident_analyzer.ai.offline import OfflineProvider

        return OfflineProvider()
    http = HTTPClient(timeout=config.timeout_seconds, max_retries=config.max_retries)
    if config.provider == "anthropic":
        return AnthropicProvider(
            api_key=environ.get("ANTHROPIC_API_KEY"),
            model=config.model,
            base_url=config.base_url,
            http=http,
        )
    if config.provider == "openai-compatible":
        return OpenAICompatibleProvider(
            api_key=environ.get("OPENAI_API_KEY"),
            model=config.model,
            base_url=config.base_url,
            http=http,
        )
    raise ConfigError(f"unknown AI provider {config.provider!r}")
