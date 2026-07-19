import json
from datetime import datetime, timedelta, timezone

import pytest

from system_info.database import HistoryDatabase, to_db_timestamp
from system_info.network_analyzer import NetworkAnalyzer
from system_info.network_models import NetworkSnapshot
from system_info.network_repository import NetworkRepository


@pytest.fixture
def network_store(tmp_path):
    database = HistoryDatabase(tmp_path / "network.db")
    database.initialize()
    repository = NetworkRepository(database)
    return database, repository, NetworkAnalyzer(repository)


def listener(
    port=8000,
    ip="127.0.0.1",
    scope="Loopback",
    path=r"C:\Apps\server.exe",
    created=100.0,
):
    return {
        "protocol": "TCP",
        "address_family": "IPv4",
        "local_ip": ip,
        "local_port": port,
        "status": "DİNLİYOR",
        "address_scope": scope,
        "externally_exposed": scope != "Loopback",
        "pid": 42,
        "process_name": "server.exe",
        "process_create_time": created,
        "process_path": path,
        "username": "user",
        "parent_pid": 1,
        "parent_process_name": "parent.exe",
        "command_line": "server.exe",
    }


def connection(
    ip="8.8.8.8",
    port=443,
    pid=42,
    name="client.exe",
    created=None,
):
    return {
        "protocol": "TCP",
        "address_family": "IPv4",
        "local_ip": "10.0.0.2",
        "local_port": 50000 + pid,
        "remote_ip": ip,
        "remote_port": port,
        "remote_scope": "Genel / public",
        "status": "BAĞLI",
        "pid": pid,
        "process_name": name,
        "process_create_time": created or datetime.now().timestamp(),
        "process_path": rf"C:\{name}",
        "username": "user",
    }


def snap(connections=(), listeners=(), when=None):
    return NetworkSnapshot(
        when or datetime.now(timezone.utc),
        tuple(connections),
        tuple(listeners),
    )


def test_listener_baseline_start_stop_and_findings(network_store) -> None:
    _db, _repo, analyzer = network_store
    assert analyzer.process(snap(listeners=[listener()]))["events"] == []
    data = analyzer.process(
        snap(listeners=[listener(), listener(9000, "0.0.0.0", "Tüm arayüzler")])
    )
    assert any(event["event_type"] == "listener_started" for event in data["events"])
    rules = {finding["rule_id"] for finding in data["findings"]}
    assert {"NET-001", "NET-002", "NET-007"} <= rules
    data = analyzer.process(snap(listeners=[listener()]))
    assert any(event["event_type"] == "listener_stopped" for event in data["events"])


def test_temp_path_listener_finding_and_deduplication(network_store) -> None:
    _db, _repo, analyzer = network_store
    analyzer.process(snap())
    item = listener(path=r"C:\Users\u\AppData\Local\Temp\server.exe")
    data = analyzer.process(snap(listeners=[item]))
    assert "NET-003" in {finding["rule_id"] for finding in data["findings"]}
    analyzer.process(snap())
    data = analyzer.process(snap(listeners=[item]))
    finding = next(row for row in data["findings"] if row["rule_id"] == "NET-003")
    assert finding["repeat_count"] == 2


def test_new_endpoint_counts_processes_and_reseen_event(network_store) -> None:
    database, _repo, analyzer = network_store
    analyzer.process(snap())
    data = analyzer.process(
        snap(connections=[connection(pid=1), connection(pid=2, name="other.exe")])
    )
    assert any(event["event_type"] == "remote_endpoint_new" for event in data["events"])
    endpoint = data["endpoints"][0]
    assert endpoint["seen_count"] == 2
    assert endpoint["seen_count_24h"] == 2
    assert endpoint["process_count"] == 2
    assert "NET-004" in {finding["rule_id"] for finding in data["findings"]}

    old = to_db_timestamp(datetime.now(timezone.utc) - timedelta(days=31))
    with database._connection() as sql, sql:
        sql.execute("UPDATE remote_endpoints SET last_seen=?", (old,))
    data = analyzer.process(snap(connections=[connection()]))
    assert any(
        event["event_type"] == "remote_endpoint_reappeared"
        for event in data["events"]
    )


def test_new_process_correlation_many_targets_and_status_updates(network_store) -> None:
    _db, repository, analyzer = network_store
    analyzer.process(snap())
    created = datetime.now().timestamp()
    connections = [
        connection(
            ip=f"8.8.4.{index}",
            port=4000 + index,
            created=created,
        )
        for index in range(1, 21)
    ]
    data = analyzer.process(snap(connections=connections))
    rules = {finding["rule_id"] for finding in data["findings"]}
    assert {"NET-004", "NET-005", "NET-006"} <= rules
    finding = data["findings"][0]
    repository.set_finding_status(finding["id"], "reviewed")
    endpoint = data["endpoints"][0]
    repository.set_expected("endpoint", endpoint["id"], True, "Kurumsal servis")
    refreshed = repository.query_dashboard()
    assert any(row["status"] == "reviewed" for row in refreshed["findings"])
    marked = next(row for row in refreshed["endpoints"] if row["id"] == endpoint["id"])
    assert marked["is_expected"] == 1
    assert marked["user_note"] == "Kurumsal servis"


def test_new_endpoint_links_recent_process_event_when_available(network_store) -> None:
    database, _repository, analyzer = network_store
    now = datetime.now(timezone.utc)
    created = now.timestamp() - 2
    analyzer.process(snap(when=now))
    database.insert_process_events(
        [
            {
                "timestamp": to_db_timestamp(now),
                "event_type": "process_started",
                "pid": 42,
                "create_time": created,
                "process_name": "client.exe",
                "parent_pid": 1,
                "parent_name": "parent.exe",
                "username": "user",
                "exe": r"C:\client.exe",
                "command_line": "client.exe",
                "first_seen": to_db_timestamp(now),
                "last_seen": to_db_timestamp(now),
            }
        ]
    )

    data = analyzer.process(
        snap(
            connections=[connection(created=created)],
            when=now + timedelta(seconds=1),
        )
    )
    event = next(row for row in data["events"] if row["event_type"] == "remote_endpoint_new")
    assert json.loads(event["details_json"])["related_process_event_id"] == 1


def test_listener_expected_note_can_be_removed(network_store) -> None:
    _db, repository, analyzer = network_store
    data = analyzer.process(snap(listeners=[listener()]))
    item = data["listeners"][0]
    repository.set_expected("listener", item["identity_key"], True, "Beklenen")
    repository.set_expected("listener", item["identity_key"], False, "")
    refreshed = repository.query_dashboard()["listeners"][0]
    assert refreshed["is_expected"] == 0
    assert refreshed["user_note"] == ""


def test_network_retention_removes_events_but_not_baseline_or_findings(
    network_store,
) -> None:
    database, repository, analyzer = network_store
    now = datetime.now(timezone.utc)
    analyzer.process(snap(when=now))
    analyzer.process(
        snap(
            connections=[connection()],
            listeners=[listener(9000)],
            when=now + timedelta(seconds=1),
        )
    )
    old = to_db_timestamp(now - timedelta(days=31))
    with database._connection() as sql, sql:
        sql.execute("UPDATE network_events SET timestamp=?", (old,))
        sql.execute("UPDATE listening_port_events SET timestamp=?", (old,))
        sql.execute(
            "INSERT INTO dns_cache VALUES (?, ?, ?, ?)",
            ("8.8.8.8", "dns.google", old, old),
        )
    deleted = database.cleanup_old_records(now=now)
    data = repository.query_dashboard()
    assert deleted["network_events"] > 0
    assert deleted["listening_events"] > 0
    assert deleted["dns_cache"] == 1
    assert data["endpoints"]
    assert data["listeners"]
    assert data["findings"]
