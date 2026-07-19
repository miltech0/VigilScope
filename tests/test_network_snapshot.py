import socket
from types import SimpleNamespace

import psutil

from system_info.network_snapshot import collect_network_snapshot


def raw_socket(
    *,
    kind=socket.SOCK_STREAM,
    family=socket.AF_INET,
    local=("0.0.0.0", 8080),
    remote=(),
    status=psutil.CONN_LISTEN,
    pid=10,
):
    return SimpleNamespace(
        type=kind,
        family=family,
        laddr=local,
        raddr=remote,
        status=status,
        pid=pid,
    )


def process(pid=10) -> dict:
    return {
        "pid": pid,
        "name": "server.exe",
        "create_time": 123.0,
        "exe": r"C:\server.exe",
        "username": "user",
        "ppid": 1,
        "parent_name": "parent.exe",
        "command_line": "server --token ***",
    }


def test_single_snapshot_separates_listeners_and_active_connections() -> None:
    calls = {"count": 0}

    def reader(kind):
        calls["count"] += 1
        return [
            raw_socket(),
            raw_socket(
                local=("10.0.0.1", 50000),
                remote=("8.8.8.8", 443),
                status=psutil.CONN_ESTABLISHED,
            ),
            raw_socket(
                kind=socket.SOCK_DGRAM,
                family=socket.AF_INET6,
                local=("::", 5353),
                status="NONE",
            ),
        ]

    snapshot = collect_network_snapshot([process()], reader)
    assert calls["count"] == 1
    assert len(snapshot.listeners) == 2
    assert len(snapshot.connections) == 2
    assert snapshot.listeners[0]["process_create_time"] == 123.0
    assert any(item["address_family"] == "IPv6" for item in snapshot.listeners)


def test_access_denied_and_no_such_process_are_safe(monkeypatch) -> None:
    def denied(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(psutil, "Process", denied)
    snapshot = collect_network_snapshot(
        net_connections=lambda kind: [raw_socket(pid=99)]
    )
    assert snapshot.listeners[0]["process_name"] == "access_denied"

    def ended(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", ended)
    snapshot = collect_network_snapshot(
        net_connections=lambda kind: [raw_socket(pid=99)]
    )
    assert snapshot.listeners[0]["process_name"] == "terminated"
