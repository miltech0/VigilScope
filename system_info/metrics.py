"""Helpers that read system measurements from the operating system."""

from __future__ import annotations

import os
import platform
import socket
from pathlib import Path
from typing import Any

import psutil


def format_bytes(value: int | float) -> str:
    """Return a byte count formatted with a readable binary unit."""
    size = float(value)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def cpu_name() -> str:
    """Return the most useful processor name available on the host."""
    name = platform.processor().strip()
    if name:
        return name

    processor_identifier = os.environ.get("PROCESSOR_IDENTIFIER", "").strip()
    return processor_identifier or "Bilinmiyor"


def collect_system_snapshot() -> dict[str, Any]:
    """Collect a point-in-time snapshot for the overview cards."""
    memory = psutil.virtual_memory()
    return {
        "computer_name": socket.gethostname(),
        "processor": cpu_name(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": memory.percent,
        "memory_used": format_bytes(memory.used),
        "memory_total": format_bytes(memory.total),
        "disks": collect_disks(),
        "active_connections": len(collect_active_connections()),
    }


def collect_disks() -> list[dict[str, Any]]:
    """Return accessible mounted disk usage, with a safe root fallback."""
    disks: list[dict[str, Any]] = []
    seen: set[str] = set()

    partitions = list(psutil.disk_partitions(all=False))
    if not partitions:
        # Some containers and restricted hosts expose no partition table even
        # though the filesystem root is queryable. Keeping a root fallback makes
        # both the application and its health checks portable.
        fallback_mount = str(Path.home().anchor or Path(os.sep))
        partitions = [
            type("Partition", (), {
                "device": fallback_mount,
                "mountpoint": fallback_mount,
            })()
        ]

    for partition in partitions:
        if partition.mountpoint in seen:
            continue
        seen.add(partition.mountpoint)

        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (PermissionError, OSError):
            continue

        disks.append(
            {
                "device": partition.device or partition.mountpoint,
                "mountpoint": partition.mountpoint,
                "percent": usage.percent,
                "used": format_bytes(usage.used),
                "total": format_bytes(usage.total),
            }
        )

    return disks


def _split_address(address: Any) -> tuple[str, str | int]:
    """Split a psutil address object into separate IP and port values."""
    if not address:
        return "—", "—"

    if hasattr(address, "ip") and hasattr(address, "port"):
        return str(address.ip), address.port
    return str(address[0]), address[1]


def _get_process_name(pid: int | None, cache: dict[int, str]) -> str:
    """Read a process name safely and cache repeated PID lookups."""
    if pid is None:
        return "Sistem"
    if pid in cache:
        return cache[pid]

    try:
        name = psutil.Process(pid).name() or "Bilinmiyor"
    except (psutil.AccessDenied, PermissionError):
        name = "Erişim yok"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        name = "Sonlandı"
    except OSError:
        name = "Bilinmiyor"

    cache[pid] = name
    return name


def collect_active_connections() -> list[dict[str, str | int]]:
    """Return the compatibility active-connection view from the shared snapshot."""
    from .network_snapshot import collect_network_snapshot

    snapshot = collect_network_snapshot()
    fields = (
        "protocol",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "status",
        "pid",
        "process_name",
    )
    return [
        {field: connection[field] for field in fields}
        for connection in snapshot.connections
    ]


def filter_connections(
    connections: list[dict[str, str | int]],
    protocol: str = "all",
    process_query: str = "",
) -> list[dict[str, str | int]]:
    """Filter connections by protocol and process name."""
    normalized_protocol = protocol.strip().upper()
    normalized_query = process_query.strip().casefold()

    return [
        connection
        for connection in connections
        if (
            normalized_protocol in {"", "TÜMÜ", "ALL"}
            or str(connection["protocol"]).upper() == normalized_protocol
        )
        and (
            not normalized_query
            or normalized_query in str(connection["process_name"]).casefold()
        )
    ]
