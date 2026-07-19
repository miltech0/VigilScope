"""Security helpers for files intended to be opened by spreadsheet software."""

from __future__ import annotations

from typing import Any

_DANGEROUS_CSV_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def sanitize_csv_value(value: Any) -> Any:
    """Prevent spreadsheet formula execution while preserving non-string values.

    CSV is a data format, but spreadsheet applications may interpret strings that
    start with formula-control characters as executable formulas. Prefixing such
    strings with an apostrophe makes them display as text in common spreadsheet
    applications. Leading whitespace is considered because some applications
    trim it before evaluating a cell.
    """
    if not isinstance(value, str):
        return value
    cleaned = value.replace("\x00", "")
    candidate = cleaned.lstrip(" \f\v")
    if candidate.startswith(_DANGEROUS_CSV_PREFIXES):
        return "'" + cleaned
    return cleaned
