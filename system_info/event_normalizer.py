"""Normalize history tables into a shared missing-field-safe event model."""

from __future__ import annotations

import json
import socket
from typing import Any

from .detection_models import NormalizedEvent
from .process_security import mask_sensitive_command_line
from .i18n import canonical_enum

UNKNOWN = "unknown"
EMPTY = "—"


def normalize_source_event(
    source_table: str,
    row: dict[str, Any],
    hostname: str | None = None,
) -> NormalizedEvent | None:
    source_id = int(row.get("id", row.get("source_record_id", 0)))
    details = _json_object(row.get("details_json"))
    evidence = _json_object(row.get("evidence_json"))
    merged = {**row, **details}
    event_type = _event_type(source_table, row)
    if event_type is None:
        return None
    command_line = (
        merged.get("command_line")
        or merged.get("masked_command_line")
        or evidence.get("command_line")
        or UNKNOWN
    )
    event: NormalizedEvent = {
        "event_id": f"{source_table}:{source_id}",
        "event_type": event_type,
        "timestamp": str(row.get("timestamp") or row.get("created_at") or ""),
        "hostname": hostname or socket.gethostname(),
        "username": str(
            merged.get("username") or evidence.get("username") or UNKNOWN
        ),
        "process_name": str(
            row.get("process_name")
            or merged.get("name")
            or evidence.get("process_name")
            or UNKNOWN
        ),
        "pid": str(row.get("pid", merged.get("pid", EMPTY))),
        "process_create_time": _float_or_none(
            merged.get("process_create_time", merged.get("create_time"))
        ),
        "parent_pid": str(
            merged.get("parent_pid", merged.get("ppid", EMPTY))
        ),
        "parent_process_name": str(
            merged.get("parent_process_name")
            or merged.get("parent_name")
            or UNKNOWN
        ),
        "executable_path": str(
            merged.get("process_path")
            or merged.get("exe")
            or evidence.get("process_path")
            or UNKNOWN
        ),
        "masked_command_line": mask_sensitive_command_line(command_line),
        "protocol": str(merged.get("protocol", EMPTY)),
        "local_ip": str(merged.get("local_ip", EMPTY)),
        "local_port": str(merged.get("local_port", EMPTY)),
        "remote_ip": str(merged.get("remote_ip", EMPTY)),
        "remote_port": str(merged.get("remote_port", EMPTY)),
        "address_scope": canonical_enum(
            "address_scope",
            merged.get("address_scope")
            or merged.get("remote_scope")
            or EMPTY,
        ),
        "source_table": source_table,
        "source_record_id": source_id,
        "additional_data": _sanitize(
            {
                **row,
                "details": details,
                "evidence": evidence,
                "is_expected": bool(row.get("is_expected", False)),
                "expected_note": str(row.get("user_note", "")),
            }
        ),
    }
    return event


def _event_type(source_table: str, row: dict[str, Any]) -> str | None:
    raw = str(row.get("event_type", ""))
    mappings = {
        "process_events": {
            "process_started": "process_started",
            "process_stopped": "process_stopped",
            "Başladı": "process_started",
            "Kapandı": "process_stopped",
        },
        "connection_events": {
            "connection_opened": "connection_opened",
            "connection_closed": "connection_closed",
            "Açıldı": "connection_opened",
            "Kapandı": "connection_closed",
        },
        "listening_port_events": {
            "listener_started": "listener_started",
            "listener_stopped": "listener_stopped",
            "Dinleme Başladı": "listener_started",
            "Dinleme Sona Erdi": "listener_stopped",
        },
        "network_events": {
            "remote_endpoint_new": "remote_endpoint_new",
            "remote_endpoint_reappeared": "remote_endpoint_reappeared",
            "Yeni Uzak Hedef": "remote_endpoint_new",
            "Uzak Hedef Yeniden Görüldü": "remote_endpoint_reappeared",
        },
        "network_findings": {"*": "network_finding"},
    }
    table_mapping = mappings.get(source_table, {})
    return table_mapping.get(raw) or table_mapping.get("*")


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _sanitize(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(item_key): _sanitize(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item, key) for item in value]
    normalized_key = key.casefold().replace("-", "_")
    if normalized_key in {
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
    }:
        return "***"
    if any(marker in key.casefold() for marker in ("command", "cmdline")):
        return mask_sensitive_command_line(value)
    if isinstance(value, str):
        return mask_sensitive_command_line(value)
    return value


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value) if value not in {None, "", EMPTY} else None
    except (TypeError, ValueError):
        return None
