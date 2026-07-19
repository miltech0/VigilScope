"""Search, filtering, and stable sorting for process records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .process_models import NUMERIC_PROCESS_FIELDS, ProcessRecord


@dataclass(frozen=True)
class ProcessFilterResult:
    records: list[ProcessRecord]
    invalid_fields: tuple[str, ...] = ()


def filter_processes(
    records: list[ProcessRecord],
    query: str = "",
    status: str = "all",
    network_only: bool = False,
    minimum_cpu: str = "",
    minimum_ram_mb: str = "",
) -> ProcessFilterResult:
    cpu, cpu_invalid = _parse_filter_number(minimum_cpu)
    ram, ram_invalid = _parse_filter_number(minimum_ram_mb)
    invalid = []
    if cpu_invalid:
        invalid.append("CPU")
    if ram_invalid:
        invalid.append("RAM")

    needle = query.strip().casefold()
    filtered = []
    for record in records:
        searchable = " ".join(
            str(record.get(field, ""))
            for field in ("name", "pid", "username", "exe")
        ).casefold()
        if needle and needle not in searchable:
            continue
        if status not in {"all", "Tümü", "All"} and record.get("status") != status:
            continue
        if network_only and int(record.get("network_count", 0)) <= 0:
            continue
        if cpu is not None and float(record.get("cpu_percent", 0.0)) < cpu:
            continue
        if ram is not None and float(record.get("ram_mb", 0.0)) < ram:
            continue
        filtered.append(record)

    return ProcessFilterResult(filtered, tuple(invalid))


def sort_processes(
    records: list[ProcessRecord], field: str, descending: bool = False
) -> list[ProcessRecord]:
    numeric = field in NUMERIC_PROCESS_FIELDS or field == "start_time"

    def key(record: ProcessRecord) -> tuple[Any, int]:
        value = record.get("create_time") if field == "start_time" else record.get(field)
        if numeric:
            try:
                normalized: Any = float(value)
            except (TypeError, ValueError):
                normalized = -1.0
        else:
            normalized = str(value or "").casefold()
        return normalized, int(record.get("pid", 0))

    return sorted(records, key=key, reverse=descending)


def _parse_filter_number(value: str) -> tuple[float | None, bool]:
    text = value.strip().replace(",", ".")
    if not text:
        return None, False
    try:
        parsed = float(text)
    except ValueError:
        return None, True
    if parsed < 0:
        return None, True
    return parsed, False
