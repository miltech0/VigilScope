"""Bounded-window sequence, count, and distinct-count correlation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .detection_models import DetectionRule, NormalizedEvent
from .rule_engine import match_condition


def correlate(
    rule: DetectionRule,
    events: list[NormalizedEvent],
    trigger: NormalizedEvent,
) -> list[NormalizedEvent] | None:
    config = rule.get("correlation") or {}
    if not config:
        return [trigger] if _single_trigger(rule, trigger) else None
    within = int(config.get("within_seconds", 60))
    trigger_time = _parse_time(trigger.get("timestamp"))
    window = [
        event
        for event in events
        if trigger_time - timedelta(seconds=within)
        <= _parse_time(event.get("timestamp"))
        <= trigger_time
        and _same_group(rule, event, trigger)
    ]
    kind = config.get("type")
    if kind in {"sequence", "followed_by"}:
        return _sequence(config.get("sequence", []), window, trigger)
    candidates = [
        event
        for event in window
        if event.get("event_type") in rule.get("event_types", [])
        and match_condition(rule.get("conditions", {}), event)
    ]
    minimum = int(config.get("minimum_count", 1))
    if kind == "count" and len(candidates) >= minimum:
        return candidates
    if kind == "distinct_count":
        field = str(config.get("distinct_field", ""))
        distinct = {_field(event, field) for event in candidates}
        distinct.discard(None)
        return candidates if len(distinct) >= minimum else None
    return None


def max_correlation_window(rules: list[DetectionRule]) -> int:
    return max(
        (
            int((rule.get("correlation") or {}).get("within_seconds", 0))
            for rule in rules
        ),
        default=0,
    )


def _single_trigger(rule: DetectionRule, trigger: NormalizedEvent) -> bool:
    from .rule_engine import rule_matches_event

    return rule_matches_event(rule, trigger)


def _sequence(
    steps: list[dict[str, Any]],
    events: list[NormalizedEvent],
    trigger: NormalizedEvent,
) -> list[NormalizedEvent] | None:
    if not steps or trigger.get("event_type") != steps[-1].get("event_type"):
        return None
    ordered = sorted(events, key=lambda event: str(event.get("timestamp", "")))
    trigger_index = next(
        (
            index
            for index in range(len(ordered) - 1, -1, -1)
            if ordered[index].get("event_id") == trigger.get("event_id")
        ),
        -1,
    )
    if trigger_index < 0 or not match_condition(
        steps[-1].get("conditions", {}),
        trigger,
    ):
        return None
    evidence: list[NormalizedEvent] = [trigger]
    search_before = trigger_index
    for step in reversed(steps[:-1]):
        match_index = next(
            (
                index
                for index in range(search_before - 1, -1, -1)
                if ordered[index].get("event_type") == step.get("event_type")
                and match_condition(step.get("conditions", {}), ordered[index])
            ),
            -1,
        )
        if match_index < 0:
            return None
        evidence.append(ordered[match_index])
        search_before = match_index
    return list(reversed(evidence))


def _same_group(
    rule: DetectionRule,
    left: NormalizedEvent,
    right: NormalizedEvent,
) -> bool:
    fields = rule.get("group_by") or []
    return all(_field(left, field) == _field(right, field) for field in fields)


def _field(event: dict[str, Any], field: str) -> Any:
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _parse_time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
