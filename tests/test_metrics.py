import socket
from types import SimpleNamespace

import psutil

from system_info.metrics import (
    collect_active_connections,
    collect_disks,
    collect_system_snapshot,
    filter_connections,
    format_bytes,
)


def test_format_bytes() -> None:
    assert format_bytes(0) == "0.0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024**3) == "1.0 GB"


def test_snapshot_contains_expected_fields() -> None:
    snapshot = collect_system_snapshot()
    assert snapshot["computer_name"]
    assert 0 <= snapshot["cpu_percent"] <= 100
    assert 0 <= snapshot["memory_percent"] <= 100
    assert isinstance(snapshot["disks"], list)


def test_at_least_one_disk_is_visible() -> None:
    assert collect_disks()


def test_connection_addresses_and_process_name_are_separate(monkeypatch) -> None:
    connection = SimpleNamespace(
        type=socket.SOCK_STREAM,
        laddr=("127.0.0.1", 54321),
        raddr=("203.0.113.10", 443),
        status=psutil.CONN_ESTABLISHED,
        pid=42,
    )

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            assert pid == 42

        def name(self) -> str:
            return "örnek.exe"

    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", FakeProcess)

    result = collect_active_connections()

    assert result == [
        {
            "protocol": "TCP",
            "local_ip": "127.0.0.1",
            "local_port": 54321,
            "remote_ip": "203.0.113.10",
            "remote_port": 443,
            "status": "connected",
            "pid": 42,
            "process_name": "örnek.exe",
        }
    ]


def test_access_denied_process_is_reported_without_crashing(monkeypatch) -> None:
    connection = SimpleNamespace(
        type=socket.SOCK_DGRAM,
        laddr=("0.0.0.0", 5353),
        raddr=(),
        status="NONE",
        pid=99,
    )

    def denied_process(pid: int) -> None:
        raise psutil.AccessDenied(pid=pid)

    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", denied_process)

    result = collect_active_connections()

    assert result[0]["process_name"] == "access_denied"
    assert result[0]["remote_ip"] == "—"
    assert result[0]["remote_port"] == "—"


def test_connections_can_be_filtered_by_protocol_and_process_name() -> None:
    connections = [
        {"protocol": "TCP", "process_name": "python.exe"},
        {"protocol": "UDP", "process_name": "chrome.exe"},
        {"protocol": "TCP", "process_name": "System"},
    ]

    assert filter_connections(connections, protocol="TCP") == [
        connections[0],
        connections[2],
    ]
    assert filter_connections(connections, process_query="CHROME") == [connections[1]]
    assert filter_connections(connections, protocol="UDP", process_query="python") == []
