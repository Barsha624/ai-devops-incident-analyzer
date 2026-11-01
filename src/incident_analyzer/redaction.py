from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from typing import Any

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL
)
_URL_CREDENTIALS = re.compile(r"(\b[a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.IGNORECASE)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER = re.compile(r"\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_KEY_VALUE = re.compile(
    r"""\b([\w-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|
    authorization|credential)[\w-]*)(["']?\s*[:=]\s*["']?)([^\s"',;&}]+)""",
    re.IGNORECASE | re.VERBOSE,
)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")

_REDACTED = "[REDACTED:{}]"

# Fields of the report that are free text taken from logs. Everything else (ids, counts,
# timestamps, severity) is structured data produced by this tool and is left untouched.
_TEXT_FIELDS = frozenset({"excerpt", "title", "signature", "snippet"})


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def redact_with_counts(text: str) -> tuple[str, Counter[str]]:
    """Return ``(redacted_text, how_many_of_each_kind_were_replaced)``."""
    counts: Counter[str] = Counter()

    def tag(kind: str) -> Callable[[re.Match[str]], str]:
        def replace(_: re.Match[str]) -> str:
            counts[kind] += 1
            return _REDACTED.format(kind)

        return replace

    def url_credentials(match: re.Match[str]) -> str:
        counts["url-credentials"] += 1
        return f"{match.group(1)}{_REDACTED.format('credentials')}@"

    def bearer(match: re.Match[str]) -> str:
        counts["token"] += 1
        return f"{match.group(1)}{match.group(2)}{_REDACTED.format('token')}"

    def key_value(match: re.Match[str]) -> str:
        if match.group(3).startswith("[REDACTED"):
            return match.group(0)
        counts["secret"] += 1
        return f"{match.group(1)}{match.group(2)}{_REDACTED.format('secret')}"

    def card(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            counts["card-number"] += 1
            return _REDACTED.format("card-number")
        return match.group(0)

    text = _PRIVATE_KEY.sub(tag("private-key"), text)
    text = _URL_CREDENTIALS.sub(url_credentials, text)
    text = _JWT.sub(tag("jwt"), text)
    text = _AWS_ACCESS_KEY.sub(tag("aws-access-key"), text)
    text = _BEARER.sub(bearer, text)
    text = _KEY_VALUE.sub(key_value, text)
    text = _EMAIL.sub(tag("email"), text)
    text = _CARD_CANDIDATE.sub(card, text)
    text = _IPV4.sub(tag("ip"), text)
    text = _LONG_TOKEN.sub(tag("token"), text)
    return text, counts


def redact_text(text: str) -> str:
    """Redact secrets and obvious personal data from one string."""
    return redact_with_counts(text)[0]


def redact_report(node: Any) -> None:
    """Redact free-text log fields of a report dict **in place** (recursively)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _TEXT_FIELDS and isinstance(value, str):
                node[key] = redact_text(value)
            else:
                redact_report(value)
    elif isinstance(node, list):
        for item in node:
            redact_report(item)
