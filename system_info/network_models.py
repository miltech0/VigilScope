"""Explicit types for passive network snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, TypedDict


class NetworkConnection(TypedDict, total=False):
    protocol: str
    address_family: str
    local_ip: str
    local_port: int | str
    remote_ip: str
    remote_port: int | str
    remote_scope: str
    status: str
    pid: int | str
    process_name: str
    process_create_time: float | None
    process_path: str
    username: str
    parent_pid: int
    parent_process_name: str
    command_line: str


class ListeningPort(TypedDict, total=False):
    protocol: str
    address_family: str
    local_ip: str
    local_port: int | str
    status: str
    address_scope: str
    externally_exposed: bool
    pid: int | str
    process_name: str
    process_create_time: float | None
    process_path: str
    username: str
    parent_pid: int
    parent_process_name: str
    command_line: str


@dataclass(frozen=True)
class NetworkSnapshot:
    captured_at: datetime
    connections: tuple[NetworkConnection, ...]
    listeners: tuple[ListeningPort, ...]

    def process_counts(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for connection in self.connections:
            pid = connection.get("pid")
            if isinstance(pid, int):
                counts[pid] = counts.get(pid, 0) + 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at.isoformat(),
            "connections": [dict(item) for item in self.connections],
            "listeners": [dict(item) for item in self.listeners],
        }
