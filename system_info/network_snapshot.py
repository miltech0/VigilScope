"""Build a shared passive snapshot from one psutil.net_connections call."""

from __future__ import annotations

import socket
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

import psutil

from .address_utils import address_family, classify_ip, is_externally_exposed
from .network_models import ListeningPort, NetworkConnection, NetworkSnapshot
from .process_models import ACCESS_DENIED, ENDED, UNKNOWN, ProcessRecord
from .process_security import mask_sensitive_command_line


def collect_network_snapshot(
    process_records: list[ProcessRecord] | None = None,
    net_connections: Any = None,
) -> NetworkSnapshot:
    """Yerel socket tablosunu bir kez okuyup aktif bağlantı ve dinleyicilere ayırır."""
    process_index = {
        int(record["pid"]): record for record in (process_records or [])
    }
    reader = net_connections or psutil.net_connections
    try:
        raw_connections = reader(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        raw_connections = []

    metadata_cache: dict[int, dict[str, Any]] = {}
    connections: list[NetworkConnection] = []
    listeners: list[ListeningPort] = []
    for raw in raw_connections:
        protocol = "TCP" if raw.type == socket.SOCK_STREAM else "UDP"
        local_ip, local_port = _split_address(raw.laddr)
        remote_ip, remote_port = _split_address(raw.raddr)
        raw_family = getattr(raw, "family", None)
        family = (
            "IPv6"
            if raw_family == socket.AF_INET6
            else "IPv4"
            if raw_family == socket.AF_INET
            else address_family(local_ip)
        )
        pid = raw.pid if raw.pid is not None else "—"
        metadata = _process_metadata(pid, process_index, metadata_cache)
        status = raw.status or "none"

        is_tcp_listener = protocol == "TCP" and status == psutil.CONN_LISTEN
        is_udp_listener = protocol == "UDP" and bool(raw.laddr)
        if is_tcp_listener or is_udp_listener:
            scope = classify_ip(local_ip)
            listeners.append(
                {
                    "protocol": protocol,
                    "address_family": family,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "status": "listening",
                    "address_scope": scope,
                    "externally_exposed": is_externally_exposed(scope),
                    "pid": pid,
                    **metadata,
                }
            )

        is_tcp_active = protocol == "TCP" and status == psutil.CONN_ESTABLISHED
        is_udp_active = protocol == "UDP" and bool(raw.laddr)
        if is_tcp_active or is_udp_active:
            connections.append(
                {
                    "protocol": protocol,
                    "address_family": family,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "remote_scope": classify_ip(remote_ip),
                    "status": "connected" if is_tcp_active else "listening",
                    "pid": pid,
                    **metadata,
                }
            )

    def sort_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
        return (
            str(item["protocol"]),
            str(item["local_ip"]),
            str(item["local_port"]),
            str(item.get("remote_ip", "")),
        )

    return NetworkSnapshot(
        captured_at=datetime.now(timezone.utc),
        connections=tuple(sorted(connections, key=sort_key)),
        listeners=tuple(sorted(listeners, key=sort_key)),
    )


def _split_address(address: Any) -> tuple[str, int | str]:
    if not address:
        return "—", "—"
    if hasattr(address, "ip"):
        return str(address.ip), address.port
    return str(address[0]), address[1]


def _process_metadata(
    pid: int | str,
    process_index: dict[int, ProcessRecord],
    cache: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(pid, int):
        return _unknown_metadata()
    if pid in process_index:
        record = process_index[pid]
        return {
            "process_name": record.get("name", UNKNOWN),
            "process_create_time": record.get("create_time"),
            "process_path": record.get("exe", UNKNOWN),
            "username": record.get("username", UNKNOWN),
            "parent_pid": int(record.get("ppid", 0)),
            "parent_process_name": record.get("parent_name", UNKNOWN),
            "command_line": mask_sensitive_command_line(
                record.get("command_line")
            ),
        }
    if pid in cache:
        return cache[pid]
    cache[pid] = _read_process_metadata(pid)
    return cache[pid]


def _read_process_metadata(pid: int) -> dict[str, Any]:
    try:
        process = psutil.Process(pid)
        context = process.oneshot() if hasattr(process, "oneshot") else nullcontext()
        with context:
            parent_pid = _safe_process_call(process, "ppid", 0)
            try:
                parent_name = psutil.Process(parent_pid).name() if isinstance(parent_pid, int) and parent_pid else UNKNOWN
            except (psutil.Error, OSError):
                parent_name = UNKNOWN
            return {
                "process_name": _safe_process_call(process, "name", UNKNOWN),
                "process_create_time": _safe_process_call(process, "create_time", None),
                "process_path": _safe_process_call(process, "exe", UNKNOWN),
                "username": _safe_process_call(process, "username", UNKNOWN),
                "parent_pid": parent_pid,
                "parent_process_name": parent_name,
                "command_line": mask_sensitive_command_line(
                    _safe_process_call(process, "cmdline", UNKNOWN)
                ),
            }
    except (psutil.AccessDenied, PermissionError):
        return {
            **_unknown_metadata(),
            "process_name": ACCESS_DENIED,
            "process_path": ACCESS_DENIED,
            "username": ACCESS_DENIED,
            "command_line": ACCESS_DENIED,
        }
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return {
            **_unknown_metadata(),
            "process_name": ENDED,
            "process_path": ENDED,
            "username": ENDED,
            "command_line": ENDED,
        }
    except OSError:
        return _unknown_metadata()


def _unknown_metadata() -> dict[str, Any]:
    return {
        "process_name": UNKNOWN,
        "process_create_time": None,
        "process_path": UNKNOWN,
        "username": UNKNOWN,
        "parent_pid": 0,
        "parent_process_name": UNKNOWN,
        "command_line": UNKNOWN,
    }


def _safe_process_call(process: Any, name: str, default: Any) -> Any:
    try:
        value = getattr(process, name)()
        return value if value is not None and value != "" else default
    except (psutil.AccessDenied, PermissionError):
        return ACCESS_DENIED
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return ENDED
    except (AttributeError, OSError, RuntimeError, ValueError):
        return default
