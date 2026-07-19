"""Masked UTF-8 exports for alerts, cases, rules, and suppressions."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .alert_repository import AlertRepository
from .database import to_db_timestamp
from .export_security import sanitize_csv_value
from .i18n import I18n, get_i18n
from .process_security import mask_sensitive_command_line
from .product import PRODUCT_NAME


def build_detection_bundle(
    repository: AlertRepository,
    limit: int = 100_000,
) -> dict[str, Any]:
    dashboard = repository.dashboard(limit)
    alert_details = [
        repository.alert_details(int(alert["id"]))
        for alert in dashboard["alerts"]
    ]
    case_details = [
        repository.case_details(int(case["id"]))
        for case in dashboard["cases"]
    ]
    return _sanitize(
        {
            "alerts": dashboard["alerts"],
            "alert_details": alert_details,
            "cases": dashboard["cases"],
            "case_details": case_details,
            "rules": dashboard["rules"],
            "suppressions": dashboard["suppressions"],
            "attack_coverage": dashboard["attack_coverage"],
        }
    )


def export_detection_json(
    path: str | Path,
    repository: AlertRepository,
) -> None:
    payload = {
        "metadata": {
            "product": PRODUCT_NAME,
            "display_language": get_i18n().language,
            "exported_at": to_db_timestamp(),
        },
        **build_detection_bundle(repository),
    }
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def export_detection_csv(
    path: str | Path,
    repository: AlertRepository,
    *,
    i18n: I18n | None = None,
) -> None:
    payload = build_detection_bundle(repository)
    fields = (
        "record_type",
        "id",
        "timestamp",
        "rule_id",
        "title",
        "severity",
        "status",
        "process_name",
        "pid",
        "remote_address",
        "payload_json",
    )
    translator = i18n or get_i18n()
    headers = {field: translator.t(f"exports.fields.{field}") for field in fields}
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(headers.values()))
        writer.writeheader()
        for kind in (
            "alerts",
            "alert_details",
            "cases",
            "case_details",
            "rules",
            "suppressions",
            "attack_coverage",
        ):
            for record in payload[kind]:
                row = {
                        "record_type": kind,
                        "id": record.get("id", record.get("rule_id", "")),
                        "timestamp": record.get(
                            "last_seen",
                            record.get("updated_at", record.get("created_at", "")),
                        ),
                        "rule_id": record.get("rule_id", ""),
                        "title": record.get("title", record.get("name", "")),
                        "severity": record.get("severity", ""),
                        "status": record.get("status", ""),
                        "process_name": record.get("process_name", ""),
                        "pid": record.get("pid", ""),
                        "remote_address": record.get("remote_address", ""),
                        "payload_json": json.dumps(
                            record,
                            ensure_ascii=False,
                            default=str,
                        ),
                    }
                writer.writerow(
                    {headers[key]: sanitize_csv_value(value) for key, value in row.items()}
                )


def export_single_alert_json(
    path: str | Path,
    repository: AlertRepository,
    alert_id: int,
) -> None:
    _write_json(path, _sanitize(repository.alert_details(alert_id)))


def export_single_case_json(
    path: str | Path,
    repository: AlertRepository,
    case_id: int,
) -> None:
    _write_json(path, _sanitize(repository.case_details(case_id)))


def _write_json(path: str | Path, payload: Any) -> None:
    if isinstance(payload, dict):
        payload = {
            "metadata": {
                "product": PRODUCT_NAME,
                "display_language": get_i18n().language,
                "exported_at": to_db_timestamp(),
            },
            **payload,
        }
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def _sanitize(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize(item, str(item_key))
            for item_key, item in value.items()
        }
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
