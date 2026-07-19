"""Mask common sensitive values in command lines."""

from __future__ import annotations

import re
from collections.abc import Sequence

_PATTERNS = (
    re.compile(
        r"(?i)(--(?:password|token|api[-_]key)(?:\s+|=))"
        r"(\"[^\"]*\"|'[^']*'|[^\s]+)"
    ),
    re.compile(
        r"(?i)((?:password|token|api_key)\s*=\s*)"
        r"(\"[^\"]*\"|'[^']*'|[^\s]+)"
    ),
    re.compile(r"(?i)(Authorization\s*:?\s*Bearer\s+)([^\s]+)"),
)


def mask_sensitive_command_line(value: str | Sequence[str] | None) -> str:
    """Bilinen parola/token biçimlerini normal argümanlara dokunmadan maskeler."""
    if value is None:
        return "Bilinmiyor"
    text = " ".join(str(part) for part in value) if not isinstance(value, str) else value
    for pattern in _PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}***", text)
    return text or "Bilinmiyor"
