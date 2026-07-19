"""Safely load built-in and user-authored JSON detection rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detection_models import DetectionRule
from .i18n import I18n, get_i18n
from .rule_validator import RuleValidationError, validate_rule

BUILTIN_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "builtin_rules.json"
MAX_RULE_FILE_BYTES = 2 * 1024 * 1024
MAX_SINGLE_RULE_BYTES = 256 * 1024
MAX_RULES_PER_FILE = 1000


def localized_builtin_rule(
    rule: dict[str, Any],
    i18n: I18n | None = None,
) -> dict[str, Any]:
    """Return localized display fields for a built-in rule without changing logic."""
    if not rule.get("_metadata", {}).get("is_builtin") and not rule.get("title_key"):
        return dict(rule)
    translator = i18n or get_i18n()
    rule_id = str(rule.get("id") or rule.get("rule_id") or "")
    result = dict(rule)
    for field in ("title", "description", "category"):
        key = str(rule.get(f"{field}_key") or f"rules.{rule_id}.{field}")
        result[field] = translator.optional(key, str(rule.get(field, "")))
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuleValidationError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RuleValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise RuleValidationError(
            f"JSON line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except (RecursionError, MemoryError) as exc:
        raise RuleValidationError("Rule JSON is too deeply nested or too large") from exc


def _read_limited_text(path: str | Path, max_bytes: int) -> str:
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise RuleValidationError(f"Could not inspect rule file: {exc}") from exc
    if size > max_bytes:
        raise RuleValidationError(
            f"Rule file is too large ({size} bytes; limit is {max_bytes})"
        )
    try:
        return file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuleValidationError(f"Could not read rule file: {exc}") from exc


def load_rule_file(path: str | Path = BUILTIN_RULES_PATH) -> list[DetectionRule]:
    payload = _parse_json(_read_limited_text(path, MAX_RULE_FILE_BYTES))
    raw_rules = payload.get("rules") if isinstance(payload, dict) else payload
    if not isinstance(raw_rules, list):
        raise RuleValidationError("Rule file root must be a rules list")
    if len(raw_rules) > MAX_RULES_PER_FILE:
        raise RuleValidationError(
            f"Rule file may contain at most {MAX_RULES_PER_FILE} rules"
        )
    rules: list[DetectionRule] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_rules):
        if not isinstance(item, dict):
            raise RuleValidationError(f"rules[{index}]: rule must be an object")
        try:
            rule = validate_rule(item)
        except RuleValidationError as exc:
            raise RuleValidationError(f"rules[{index}]: {exc}") from exc
        if rule["id"] in seen:
            raise RuleValidationError(f"rules[{index}].id: duplicate {rule['id']}")
        seen.add(rule["id"])
        rules.append(rule)
    return rules


def load_single_rule_file(path: str | Path) -> DetectionRule:
    """Load exactly one user rule from a size-limited UTF-8 JSON file."""
    return parse_rule_text(_read_limited_text(path, MAX_SINGLE_RULE_BYTES))


def parse_rule_text(text: str) -> DetectionRule:
    if len(text.encode("utf-8")) > MAX_SINGLE_RULE_BYTES:
        raise RuleValidationError(
            f"Rule JSON is too large; limit is {MAX_SINGLE_RULE_BYTES} bytes"
        )
    payload = _parse_json(text)
    if not isinstance(payload, dict):
        raise RuleValidationError("Rule JSON must be an object")
    return validate_rule(payload)


def rule_to_json(rule: dict[str, Any]) -> str:
    return json.dumps(rule, ensure_ascii=False, indent=2, sort_keys=False)
