"""Shared event, rule, and alert types for the detection engine."""

from __future__ import annotations

from typing import Any, TypedDict

EVENT_TYPES = {
    "process_started",
    "process_stopped",
    "connection_opened",
    "connection_closed",
    "listener_started",
    "listener_stopped",
    "remote_endpoint_new",
    "remote_endpoint_reappeared",
    "network_finding",
}

SEVERITIES = ("info", "low", "medium", "high", "critical")
ALERT_STATUSES = (
    "new",
    "investigating",
    "confirmed",
    "false_positive",
    "ignored",
    "closed",
)
CASE_STATUSES = (
    "open",
    "investigating",
    "on_hold",
    "resolved",
    "false_positive",
    "closed",
)


class NormalizedEvent(TypedDict, total=False):
    event_id: str
    event_type: str
    timestamp: str
    hostname: str
    username: str
    process_name: str
    pid: str
    process_create_time: float | None
    parent_pid: str
    parent_process_name: str
    executable_path: str
    masked_command_line: str
    protocol: str
    local_ip: str
    local_port: str
    remote_ip: str
    remote_port: str
    address_scope: str
    source_table: str
    source_record_id: int
    additional_data: dict[str, Any]


class DetectionRule(TypedDict, total=False):
    id: str
    title: str
    description: str
    enabled: bool
    severity: str
    category: str
    event_types: list[str]
    conditions: dict[str, Any]
    correlation: dict[str, Any]
    group_by: list[str]
    deduplication: dict[str, Any]
    mitre_attack: list[dict[str, str]]
    false_positives: list[str]
    investigation_steps: list[str]
    tags: list[str]
    version: str
