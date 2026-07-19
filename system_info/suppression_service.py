"""User-approved alert suppressions that preserve source events."""

from __future__ import annotations

from typing import Any

from .alert_repository import AlertRepository
from .detection_models import NormalizedEvent
from .rule_engine import match_condition
from .rule_validator import validate_rule


class SuppressionService:
    def __init__(self, repository: AlertRepository) -> None:
        self.repository = repository

    def matching_suppression(
        self,
        event: NormalizedEvent,
    ) -> dict[str, Any] | None:
        for suppression in self.repository.active_suppressions():
            conditions = suppression.get("match_conditions", {})
            try:
                if match_condition(conditions, event):
                    return suppression
            except (TypeError, ValueError):
                continue
        return None

    def create(
        self,
        name: str,
        conditions: dict[str, Any],
        reason: str,
        expires_at: str | None = None,
    ) -> tuple[int, bool]:
        # Validate condition syntax with the same safe rule validator.
        probe = {
            "id": "SUP-PROBE",
            "title": "Susturma doğrulaması",
            "description": "Susturma koşulu doğrulaması",
            "enabled": True,
            "severity": "info",
            "category": "Susturma",
            "event_types": ["process_started"],
            "conditions": conditions,
        }
        validate_rule(probe)
        broad = _is_broad(conditions)
        return (
            self.repository.create_suppression(
                name,
                conditions,
                reason,
                expires_at,
            ),
            broad,
        )


def _is_broad(condition: dict[str, Any]) -> bool:
    if "all" in condition:
        return len(condition["all"]) <= 1
    if "any" in condition:
        return True
    field = str(condition.get("field", ""))
    return field in {"process_name", "username", "rule_id"} or not field
