"""Shared process record fields and safe normalization helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

ACCESS_DENIED = "access_denied"
ENDED = "terminated"
UNKNOWN = "unknown"

ProcessRecord = dict[str, Any]
ProcessIdentity = tuple[int, float | None]

STATUS_LABELS = {
    "running": "running",
    "sleeping": "sleeping",
    "disk-sleep": "disk_sleep",
    "stopped": "stopped",
    "tracing-stop": "tracing_stop",
    "zombie": "zombie",
    "dead": "terminated",
    "wake-kill": "terminating",
    "waking": "waking",
    "idle": "idle",
    "locked": "locked",
    "waiting": "waiting",
    "parked": "parked",
}

NUMERIC_PROCESS_FIELDS = {
    "pid",
    "ppid",
    "cpu_percent",
    "ram_mb",
    "ram_percent",
    "num_threads",
    "create_time",
    "network_count",
}


def process_identity(record: ProcessRecord) -> ProcessIdentity:
    create_time = record.get("create_time")
    normalized_time = (
        float(create_time) if isinstance(create_time, (int, float)) else None
    )
    return int(record["pid"]), normalized_time


def identity_text(identity: ProcessIdentity) -> str:
    pid, create_time = identity
    suffix = "unknown" if create_time is None else f"{create_time:.6f}"
    return f"process:{pid}:{suffix}"


def normalize_process_data(
    raw: dict[str, Any], network_count: int = 0
) -> ProcessRecord:
    """Convert raw psutil values into a stable, safe process record."""
    pid = _integer(raw.get("pid"), 0)
    create_time = _optional_float(raw.get("create_time"))
    ram_bytes = _integer(raw.get("ram_bytes"), 0)
    raw_status = raw.get("status", UNKNOWN)
    status = STATUS_LABELS.get(str(raw_status), str(raw_status or UNKNOWN))
    if raw.get("_ended"):
        status = ENDED

    return {
        "name": _text(raw.get("name")),
        "pid": pid,
        "ppid": _integer(raw.get("ppid"), 0),
        "parent_name": _text(raw.get("parent_name")),
        "username": _text(raw.get("username")),
        "status": status,
        "cpu_percent": max(0.0, _number(raw.get("cpu_percent"), 0.0)),
        "ram_bytes": max(0, ram_bytes),
        "ram_mb": max(0.0, ram_bytes / (1024 * 1024)),
        "ram_percent": max(0.0, _number(raw.get("ram_percent"), 0.0)),
        "num_threads": max(0, _integer(raw.get("num_threads"), 0)),
        "create_time": create_time,
        "start_time": format_start_time(create_time),
        "exe": _text(raw.get("exe")),
        "cwd": _text(raw.get("cwd")),
        "command_line": _text(raw.get("command_line")),
        "network_count": max(0, int(network_count)),
    }


def format_start_time(create_time: float | None) -> str:
    if create_time is None:
        return UNKNOWN
    try:
        return datetime.fromtimestamp(create_time).strftime("%d.%m.%Y %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return UNKNOWN


def format_uptime(create_time: float | None, now: float) -> str:
    if create_time is None:
        return UNKNOWN
    seconds = max(0, int(now - create_time))
    days, remainder = divmod(seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f"{days} gün {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _text(value: Any) -> str:
    if value is None or value == "":
        return UNKNOWN
    return str(value)


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _number(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _optional_float(value: Any) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    return float(value)
