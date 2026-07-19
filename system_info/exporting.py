"""Export history records to UTF-8 CSV and canonical JSON files."""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .database import to_db_timestamp
from .export_security import sanitize_csv_value
from .i18n import I18n, get_i18n
from .process_security import mask_sensitive_command_line
from .product import PRODUCT_NAME

CSV_FIELDS = (
    "record_type",
    "timestamp",
    "cpu_percent",
    "ram_percent",
    "ram_used_bytes",
    "disk_percent",
    "active_connections",
    "net_bytes_sent",
    "net_bytes_recv",
    "event_type",
    "protocol",
    "pid",
    "process_name",
    "local_ip",
    "local_port",
    "remote_ip",
    "remote_port",
    "status",
    "create_time",
    "parent_pid",
    "parent_name",
    "username",
    "exe",
    "command_line",
    "first_seen",
    "last_seen",
    "rule_id",
    "severity",
    "title",
    "description",
    "address_scope",
    "local_address",
    "remote_address",
    "evidence_json",
    "details_json",
    "repeat_count",
)


def export_history_csv(
    path: str | Path,
    measurements: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    process_events: Sequence[Mapping[str, Any]] = (),
    network_events: Sequence[Mapping[str, Any]] = (),
    network_findings: Sequence[Mapping[str, Any]] = (),
    *,
    i18n: I18n | None = None,
) -> None:
    """Write all history record types to one language-aware CSV file."""
    translator = i18n or get_i18n()
    headers = {field: translator.t(f"exports.fields.{field}") for field in CSV_FIELDS}
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=tuple(headers.values()),
            extrasaction="ignore",
        )
        writer.writeheader()

        def write(record: Mapping[str, Any]) -> None:
            writer.writerow(
                {
                    headers[key]: sanitize_csv_value(value)
                    for key, value in record.items()
                    if key in headers
                }
            )

        for measurement in measurements:
            write({"record_type": "measurement", **measurement})
        for event in events:
            write({"record_type": "connection_event", **event})
        for event in process_events:
            write(
                {
                    "record_type": "process_event",
                    **event,
                    "command_line": mask_sensitive_command_line(
                        event.get("command_line")
                    ),
                }
            )
        for event in network_events:
            write({"record_type": "network_event", **event})
        for finding in network_findings:
            write({"record_type": "network_finding", **finding})


def export_history_json(
    path: str | Path,
    measurements: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    process_events: Sequence[Mapping[str, Any]] = (),
    network_events: Sequence[Mapping[str, Any]] = (),
    network_findings: Sequence[Mapping[str, Any]] = (),
    *,
    display_language: str | None = None,
) -> None:
    safe_process_events = [
        {
            **event,
            "command_line": mask_sensitive_command_line(event.get("command_line")),
        }
        for event in process_events
    ]
    payload = {
        "metadata": {
            "product": PRODUCT_NAME,
            "display_language": display_language or get_i18n().language,
            "exported_at": to_db_timestamp(),
        },
        "system_measurements": list(measurements),
        "connection_events": list(events),
        "process_events": safe_process_events,
        "network_events": list(network_events),
        "network_findings": list(network_findings),
    }
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
