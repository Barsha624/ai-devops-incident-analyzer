"""Turn variable log messages into stable fingerprints ("signatures").

``Timeout after 30001ms calling 10.0.3.7`` and ``Timeout after 29987ms calling 10.0.3.9`` are
the same problem. Replacing the variable parts (numbers, IPs, ids, quoted values) with
placeholders makes both produce the same signature, so they can be counted together.
"""

from __future__ import annotations

import re

MAX_SIGNATURE_CHARS = 120

_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_HEX = re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b", re.I)
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_NUMBER = re.compile(r"(?<!\w)\d+(?:\.\d+)?")  # also matches the 30001 in "30001ms"
_SPACES = re.compile(r"\s+")


def normalize_message(message: str, max_chars: int = MAX_SIGNATURE_CHARS) -> str:
    """Replace variable tokens with placeholders and collapse whitespace."""
    text = _UUID.sub("<uuid>", message)
    text = _IPV4.sub("<ip>", text)
    text = _HEX.sub("<hex>", text)
    text = _QUOTED.sub("<str>", text)
    text = _NUMBER.sub("<n>", text)
    text = _SPACES.sub(" ", text).strip()
    return text[:max_chars]


def normalize_path(path: str) -> str:
    """``/orders/123/items?x=1`` -> ``/orders/<id>/items`` (so URLs group by route)."""
    clean = path.split("?", 1)[0].split("#", 1)[0]
    parts = []
    for segment in clean.split("/"):
        if segment.isdigit() or _UUID.fullmatch(segment) or _HEX.fullmatch(segment):
            parts.append("<id>")
        else:
            parts.append(segment)
    return "/".join(parts) or "/"
