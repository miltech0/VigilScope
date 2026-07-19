"""Safe field comparisons and single-event rule evaluation."""

from __future__ import annotations

import fnmatch
from typing import Any

from .detection_models import DetectionRule, NormalizedEvent
from .rule_validator import RuleValidationError, safe_regex_search, validate_regex
from .i18n import canonical_enum


def rule_matches_event(rule: DetectionRule, event: NormalizedEvent) -> bool:
    return bool(
        rule.get("enabled", True)
        and event.get("event_type") in rule.get("event_types", [])
        and match_condition(rule.get("conditions", {}), event)
    )


def match_condition(condition: dict[str, Any], event: dict[str, Any]) -> bool:
    if not condition:
        return True
    if "all" in condition:
        return all(match_condition(item, event) for item in condition["all"])
    if "any" in condition:
        return any(match_condition(item, event) for item in condition["any"])
    if "not" in condition:
        return not match_condition(condition["not"], event)
    actual = _field_value(event, str(condition.get("field", "")))
    expected = condition.get("value")
    if str(condition.get("field", "")) == "address_scope":
        actual = canonical_enum("address_scope", actual)
        if isinstance(expected, list):
            expected = [canonical_enum("address_scope", item) for item in expected]
        else:
            expected = canonical_enum("address_scope", expected)
    operator = str(condition.get("operator", "equals"))
    case_sensitive = bool(condition.get("case_sensitive", False))
    return compare(actual, operator, expected, case_sensitive)


def compare(
    actual: Any,
    operator: str,
    expected: Any,
    case_sensitive: bool = False,
) -> bool:
    if operator == "exists":
        exists = actual not in {None, "", "—", "Bilinmiyor"}
        return exists is bool(expected if expected is not None else True)
    if operator in {
        "greater_than",
        "greater_or_equal",
        "less_than",
        "less_or_equal",
    }:
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {
            "greater_than": left > right,
            "greater_or_equal": left >= right,
            "less_than": left < right,
            "less_or_equal": left <= right,
        }[operator]

    if operator in {"in", "not_in"}:
        values = expected if isinstance(expected, list) else [expected]
        result = any(_text_equal(actual, value, case_sensitive) for value in values)
        return result if operator == "in" else not result

    left = str(actual if actual is not None else "")
    right = str(expected if expected is not None else "")
    if not case_sensitive:
        left, right = left.casefold(), right.casefold()
    if operator == "equals":
        return left == right
    if operator == "not_equals":
        return left != right
    if operator == "contains":
        return right in left
    if operator == "not_contains":
        return right not in left
    if operator == "starts_with":
        return left.startswith(right)
    if operator == "ends_with":
        return left.endswith(right)
    if operator == "wildcard":
        return fnmatch.fnmatchcase(left, right)
    if operator == "regex":
        try:
            pattern = validate_regex(str(expected))
        except RuleValidationError:
            return False
        return safe_regex_search(pattern, str(actual if actual is not None else ""))
    return False


def _text_equal(left: Any, right: Any, case_sensitive: bool) -> bool:
    if case_sensitive:
        return str(left) == str(right)
    return str(left).casefold() == str(right).casefold()


def _field_value(event: dict[str, Any], field: str) -> Any:
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
