"""Strict validation for data-only JSON detection rules."""

from __future__ import annotations

import re
from typing import Any

import regex as safe_regex

from .detection_models import EVENT_TYPES, SEVERITIES
from .i18n import canonical_enum

OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "in",
    "not_in",
    "exists",
    "greater_than",
    "greater_or_equal",
    "less_than",
    "less_or_equal",
    "wildcard",
    "regex",
}
CORRELATION_TYPES = {"sequence", "count", "distinct_count", "followed_by"}
MAX_REGEX_LENGTH = 256
MAX_REGEX_SEARCH_SECONDS = 0.05
MAX_RULE_DEPTH = 10
MAX_CONDITION_CHILDREN = 100
MAX_LIST_ITEMS = 256
MAX_TEXT_LENGTH = 4096
MAX_TITLE_LENGTH = 256
MAX_FIELD_LENGTH = 128
MAX_RULE_JSON_CHARS = 128 * 1024
FIELD_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}\Z")
ALLOWED_RULE_KEYS = {
    "id", "title", "description", "enabled", "severity", "category",
    "event_types", "conditions", "correlation", "group_by", "deduplication",
    "mitre_attack", "false_positives", "investigation_steps", "tags", "version",
    "title_key", "description_key", "category_key", "_metadata",
}
ALLOWED_CORRELATION_KEYS = {
    "type", "within_seconds", "minimum_count", "distinct_field", "ordered", "sequence",
}
ALLOWED_DEDUPLICATION_KEYS = {"fields", "reopen_closed", "bucket_seconds"}


class RuleValidationError(ValueError):
    pass


def validate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise RuleValidationError("rule: must be an object")
    if len(repr(rule)) > MAX_RULE_JSON_CHARS:
        raise RuleValidationError("rule: structure is too large")

    rule = dict(rule)
    rule["severity"] = canonical_enum("severity", rule.get("severity"))
    if "conditions" in rule:
        rule["conditions"] = _canonicalize_condition(rule["conditions"])
    if isinstance(rule.get("correlation"), dict):
        correlation = dict(rule["correlation"])
        if isinstance(correlation.get("sequence"), list):
            correlation["sequence"] = [
                {
                    **step,
                    "conditions": _canonicalize_condition(step.get("conditions", {})),
                }
                if isinstance(step, dict)
                else step
                for step in correlation["sequence"]
            ]
        rule["correlation"] = correlation

    errors: list[str] = []
    unknown_keys = sorted(set(rule) - ALLOWED_RULE_KEYS)
    if unknown_keys:
        errors.append(f"rule: unknown fields: {', '.join(unknown_keys)}")

    required = ("id", "title", "description", "severity", "category", "event_types")
    for field in required:
        if field not in rule or rule[field] is None or rule[field] == "":
            errors.append(f"{field}: required field")

    rule_id = str(rule.get("id", ""))
    if not re.fullmatch(r"[A-Z][A-Z0-9_-]{2,63}", rule_id):
        errors.append("id: must be a 3-64 character uppercase letter/digit/underscore identifier")
    _validate_text(rule.get("title"), "title", errors, MAX_TITLE_LENGTH)
    _validate_text(rule.get("description"), "description", errors, MAX_TEXT_LENGTH)
    _validate_text(rule.get("category"), "category", errors, MAX_TITLE_LENGTH)
    _validate_text(rule.get("version", "1.0"), "version", errors, 64)
    for key_field in ("title_key", "description_key", "category_key"):
        if key_field in rule:
            _validate_text(rule[key_field], key_field, errors, MAX_FIELD_LENGTH)

    if rule.get("severity") not in SEVERITIES:
        errors.append(f"severity: unsupported value {rule.get('severity')!r}")
    if "enabled" in rule and not isinstance(rule["enabled"], bool):
        errors.append("enabled: must be true or false")

    event_types = rule.get("event_types")
    if not isinstance(event_types, list) or not event_types:
        errors.append("event_types: must be a non-empty list")
    elif len(event_types) > MAX_LIST_ITEMS:
        errors.append(f"event_types: may contain at most {MAX_LIST_ITEMS} values")
    else:
        unknown = sorted(set(map(str, event_types)) - EVENT_TYPES)
        if unknown:
            errors.append(f"event_types: unknown types: {', '.join(unknown)}")

    if "conditions" in rule:
        _validate_condition(rule["conditions"], "conditions", errors, 0)

    correlation = rule.get("correlation")
    if correlation:
        if not isinstance(correlation, dict):
            errors.append("correlation: must be an object")
        else:
            unknown = sorted(set(correlation) - ALLOWED_CORRELATION_KEYS)
            if unknown:
                errors.append(f"correlation: unknown fields: {', '.join(unknown)}")
            kind = correlation.get("type")
            if kind not in CORRELATION_TYPES:
                errors.append(f"correlation.type: unsupported: {kind!r}")
            within = correlation.get("within_seconds", 0)
            if not isinstance(within, (int, float)) or not 1 <= within <= 604800:
                errors.append("correlation.within_seconds: must be between 1 and 604800")
            minimum = correlation.get("minimum_count", 1)
            if not isinstance(minimum, int) or not 1 <= minimum <= 100000:
                errors.append("correlation.minimum_count: must be between 1 and 100000")
            sequence = correlation.get("sequence", [])
            if kind in {"sequence", "followed_by"}:
                if not isinstance(sequence, list) or not 2 <= len(sequence) <= MAX_LIST_ITEMS:
                    errors.append(
                        f"correlation.sequence: must contain 2-{MAX_LIST_ITEMS} steps"
                    )
                else:
                    for index, step in enumerate(sequence):
                        if not isinstance(step, dict):
                            errors.append(f"correlation.sequence[{index}]: must be an object")
                            continue
                        unknown_step = sorted(set(step) - {"event_type", "conditions"})
                        if unknown_step:
                            errors.append(
                                f"correlation.sequence[{index}]: unknown fields: "
                                f"{', '.join(unknown_step)}"
                            )
                        event_type = step.get("event_type")
                        if event_type not in EVENT_TYPES:
                            errors.append(f"correlation.sequence[{index}].event_type: unknown")
                        if "conditions" in step:
                            _validate_condition(
                                step["conditions"],
                                f"correlation.sequence[{index}].conditions",
                                errors,
                                0,
                            )
            distinct = correlation.get("distinct_field")
            if kind == "distinct_count":
                _validate_field(distinct, "correlation.distinct_field", errors)

    dedup = rule.get("deduplication")
    if dedup is not None:
        if not isinstance(dedup, dict):
            errors.append("deduplication: must be an object")
        else:
            unknown = sorted(set(dedup) - ALLOWED_DEDUPLICATION_KEYS)
            if unknown:
                errors.append(f"deduplication: unknown fields: {', '.join(unknown)}")
            _validate_field_list(dedup.get("fields", []), "deduplication.fields", errors)
            if "reopen_closed" in dedup and not isinstance(dedup["reopen_closed"], bool):
                errors.append("deduplication.reopen_closed: must be true or false")
            bucket = dedup.get("bucket_seconds")
            if bucket is not None and (
                not isinstance(bucket, (int, float)) or not 1 <= bucket <= 604800
            ):
                errors.append("deduplication.bucket_seconds: must be between 1 and 604800")

    if "group_by" in rule:
        _validate_field_list(rule["group_by"], "group_by", errors)
    for list_field in ("false_positives", "investigation_steps", "tags"):
        if list_field in rule:
            _validate_string_list(rule[list_field], list_field, errors)
    if "mitre_attack" in rule:
        _validate_mitre(rule["mitre_attack"], errors)

    if errors:
        raise RuleValidationError("\n".join(errors))

    normalized = dict(rule)
    normalized.setdefault("enabled", True)
    normalized.setdefault("conditions", {})
    normalized.setdefault("correlation", {})
    normalized.setdefault("group_by", ["pid", "process_create_time"])
    normalized.setdefault("deduplication", {"fields": normalized["group_by"]})
    normalized.setdefault("mitre_attack", [])
    normalized.setdefault("false_positives", [])
    normalized.setdefault("investigation_steps", [])
    normalized.setdefault("tags", [])
    normalized.setdefault("version", "1.0")
    return normalized


def _canonicalize_condition(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize_condition(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: _canonicalize_condition(item) for key, item in value.items()}
    if result.get("field") == "address_scope":
        if isinstance(result.get("value"), str):
            result["value"] = canonical_enum("address_scope", result["value"])
        elif isinstance(result.get("value"), list):
            result["value"] = [canonical_enum("address_scope", item) for item in result["value"]]
    return result


def validate_regex(pattern: str) -> safe_regex.Pattern[str]:
    """Compile a bounded regex; matching is still executed with a hard timeout."""
    if len(pattern) > MAX_REGEX_LENGTH:
        raise RuleValidationError(
            f"regex: may contain at most {MAX_REGEX_LENGTH} characters"
        )
    forbidden = (
        r"\\[1-9]",             # numeric backreferences
        r"\(\?P",               # named groups/backreferences
        r"\(\?\(",             # conditional groups
        r"\(\?>",               # atomic groups are unnecessary in user rules
        r"\(\?[=!<]",           # lookarounds
        r"\{\d{4,}",            # huge explicit repetitions
        r"(\*|\+|\{\d+(?:,\d*)?\})(?:\s*)(\*|\+|\{)",
        r"\([^)]*(?:\*|\+|\{\d+(?:,\d*)?\})?[^)]*\)(?:\*|\+|\{\d+)",
        r"(?:\.\*){2,}|(?:\.\+){2,}",
    )
    if any(re.search(check, pattern) for check in forbidden):
        raise RuleValidationError("regex: unsafe or excessively complex pattern rejected")
    try:
        return safe_regex.compile(pattern, safe_regex.IGNORECASE)
    except safe_regex.error as exc:
        raise RuleValidationError(f"regex: invalid pattern: {exc}") from exc


def safe_regex_search(pattern: safe_regex.Pattern[str], text: str) -> bool:
    try:
        return pattern.search(text, timeout=MAX_REGEX_SEARCH_SECONDS) is not None
    except TimeoutError:
        return False


def _validate_condition(
    condition: Any,
    path: str,
    errors: list[str],
    depth: int,
) -> None:
    if depth > MAX_RULE_DEPTH:
        errors.append(f"{path}: condition depth is too high")
        return
    if condition in ({}, None):
        return
    if not isinstance(condition, dict):
        errors.append(f"{path}: condition must be an object")
        return
    logical = [key for key in ("all", "any", "not") if key in condition]
    if logical:
        if len(logical) != 1 or len(condition) != 1:
            errors.append(f"{path}: only one AND/OR/NOT structure may be used")
            return
        key = logical[0]
        children = condition[key]
        if key == "not":
            _validate_condition(children, f"{path}.not", errors, depth + 1)
            return
        if not isinstance(children, list) or not children:
            errors.append(f"{path}.{key}: must be a non-empty list")
            return
        if len(children) > MAX_CONDITION_CHILDREN:
            errors.append(
                f"{path}.{key}: may contain at most {MAX_CONDITION_CHILDREN} conditions"
            )
            return
        for index, child in enumerate(children):
            _validate_condition(child, f"{path}.{key}[{index}]", errors, depth + 1)
        return

    unknown = sorted(set(condition) - {"field", "operator", "value", "case_sensitive"})
    if unknown:
        errors.append(f"{path}: unknown fields: {', '.join(unknown)}")
    field = condition.get("field")
    operator = condition.get("operator")
    _validate_field(field, f"{path}.field", errors)
    if operator not in OPERATORS:
        errors.append(f"{path}.operator: unsupported: {operator!r}")
        return
    if "case_sensitive" in condition and not isinstance(condition["case_sensitive"], bool):
        errors.append(f"{path}.case_sensitive: must be true or false")
    _validate_condition_value(condition.get("value"), f"{path}.value", errors)
    if operator == "regex":
        try:
            validate_regex(str(condition.get("value", "")))
        except RuleValidationError as exc:
            errors.append(f"{path}.{exc}")


def _validate_condition_value(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, str):
        if len(value) > MAX_TEXT_LENGTH:
            errors.append(f"{path}: text may contain at most {MAX_TEXT_LENGTH} characters")
        return
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            errors.append(f"{path}: may contain at most {MAX_LIST_ITEMS} values")
        for index, item in enumerate(value):
            if not isinstance(item, (str, int, float, bool)) and item is not None:
                errors.append(f"{path}[{index}]: unsupported value type")
            elif isinstance(item, str) and len(item) > MAX_TEXT_LENGTH:
                errors.append(f"{path}[{index}]: text is too long")
        return
    if not isinstance(value, (int, float, bool)) and value is not None:
        errors.append(f"{path}: unsupported value type")


def _validate_text(value: Any, path: str, errors: list[str], limit: int) -> None:
    if not isinstance(value, str):
        errors.append(f"{path}: must be text")
    elif len(value) > limit:
        errors.append(f"{path}: may contain at most {limit} characters")


def _validate_field(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not FIELD_PATTERN.fullmatch(value):
        errors.append(f"{path}: invalid field name")


def _validate_field_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        errors.append(f"{path}: must be a list with at most {MAX_LIST_ITEMS} values")
        return
    for index, field in enumerate(value):
        _validate_field(field, f"{path}[{index}]", errors)


def _validate_string_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        errors.append(f"{path}: must be a list with at most {MAX_LIST_ITEMS} values")
        return
    for index, item in enumerate(value):
        _validate_text(item, f"{path}[{index}]", errors, MAX_TEXT_LENGTH)


def _validate_mitre(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        errors.append(f"mitre_attack: must be a list with at most {MAX_LIST_ITEMS} values")
        return
    allowed = {
        "tactic_id", "tactic_name", "technique_id", "technique_name",
        "subtechnique_id", "subtechnique_name",
    }
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"mitre_attack[{index}]: must be an object")
            continue
        unknown = sorted(set(item) - allowed)
        if unknown:
            errors.append(f"mitre_attack[{index}]: unknown fields: {', '.join(unknown)}")
        for key, field_value in item.items():
            _validate_text(field_value, f"mitre_attack[{index}].{key}", errors, MAX_TITLE_LENGTH)
