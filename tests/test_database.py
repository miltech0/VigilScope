import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from system_info.database import HistoryDatabase, to_db_timestamp


@pytest.fixture
def database(tmp_path) -> HistoryDatabase:
    db = HistoryDatabase(tmp_path / "history.db")
    db.initialize()
    return db


def measurement(timestamp: datetime, cpu: float = 25.0) -> dict[str, object]:
    return {
        "timestamp": to_db_timestamp(timestamp),
        "cpu_percent": cpu,
        "ram_percent": 40.0,
        "ram_used_bytes": 4_000_000_000,
        "disk_percent": 55.0,
        "active_connections": 12,
        "net_bytes_sent": 1_000,
        "net_bytes_recv": 2_000,
    }


def event(timestamp: datetime, event_type: str = "Açıldı") -> dict[str, object]:
    return {
        "timestamp": to_db_timestamp(timestamp),
        "event_type": event_type,
        "protocol": "TCP",
        "pid": 42,
        "process_name": "örnek.exe",
        "local_ip": "127.0.0.1",
        "local_port": 50_000,
        "remote_ip": "203.0.113.10",
        "remote_port": 443,
        "status": "BAĞLI",
    }


def process_event(
    timestamp: datetime, event_type: str = "Başladı"
) -> dict[str, object]:
    return {
        "timestamp": to_db_timestamp(timestamp),
        "event_type": event_type,
        "pid": 77,
        "create_time": timestamp.timestamp() - 10,
        "process_name": "python.exe",
        "parent_pid": 10,
        "parent_name": "powershell.exe",
        "username": "kullanıcı",
        "exe": r"C:\Python\python.exe",
        "command_line": "python app.py --token gizli",
        "first_seen": to_db_timestamp(timestamp - timedelta(seconds=5)),
        "last_seen": to_db_timestamp(timestamp),
    }


def test_database_tables_are_created_idempotently(database) -> None:
    database.initialize()

    with sqlite3.connect(database.path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert database.schema_version() == 5
    assert {
        "system_measurements",
        "connection_events",
        "process_events",
        "listening_port_events",
        "listening_port_baseline",
        "remote_endpoints",
        "endpoint_process_usage",
        "endpoint_hourly_observations",
        "network_events",
        "network_findings",
        "dns_cache",
        "detection_events",
        "detection_rules",
        "detection_checkpoints",
        "alerts",
        "alert_evidence",
        "alert_notes",
        "alert_status_history",
        "cases",
        "case_alerts",
        "case_notes",
        "suppressions",
    } <= tables


def test_measurement_can_be_inserted_and_read(database) -> None:
    now = datetime.now(timezone.utc)
    database.insert_measurement(measurement(now, cpu=37.5))

    rows = database.query_measurements(now - timedelta(seconds=1))

    assert len(rows) == 1
    assert rows[0]["cpu_percent"] == 37.5
    assert rows[0]["ram_used_bytes"] == 4_000_000_000
    assert rows[0]["active_connections"] == 12


def test_measurements_are_queried_by_date_range(database) -> None:
    now = datetime.now(timezone.utc)
    database.insert_measurement(measurement(now - timedelta(hours=2), cpu=10))
    database.insert_measurement(measurement(now - timedelta(minutes=30), cpu=20))
    database.insert_measurement(measurement(now + timedelta(minutes=1), cpu=30))

    rows = database.query_measurements(
        now - timedelta(hours=1), until=now
    )

    assert [row["cpu_percent"] for row in rows] == [20.0]


def test_old_records_are_cleaned_with_separate_retention_periods(database) -> None:
    now = datetime.now(timezone.utc)
    database.insert_measurement(measurement(now - timedelta(days=8)))
    database.insert_measurement(measurement(now - timedelta(days=1)))
    database.insert_connection_events(
        [
            event(now - timedelta(days=15)),
            event(now - timedelta(days=1)),
        ]
    )
    database.insert_process_events(
        [
            process_event(now - timedelta(days=15)),
            process_event(now - timedelta(days=1)),
        ]
    )

    deleted = database.cleanup_old_records(now=now)
    measurements = database.query_measurements(now - timedelta(days=30))
    events = database.query_connection_events(now - timedelta(days=30))
    process_events = database.query_process_events(now - timedelta(days=30))

    assert deleted == {
        "measurements": 1,
        "events": 1,
        "process_events": 1,
        "listening_events": 0,
        "network_events": 0,
        "dns_cache": 0,
        "endpoint_observations": 0,
    }
    assert len(measurements) == 1
    assert len(events) == 1
    assert len(process_events) == 1


def test_empty_database_queries_return_empty_lists(database) -> None:
    since = datetime.now(timezone.utc) - timedelta(days=1)

    assert database.query_measurements(since) == []
    assert database.query_connection_events(since) == []
    assert database.query_process_events(since) == []


def test_two_database_instances_can_write_safely(tmp_path) -> None:
    path = tmp_path / "shared.db"
    first = HistoryDatabase(path)
    second = HistoryDatabase(path)
    first.initialize()
    second.initialize()
    now = datetime.now(timezone.utc)

    def write_many(database: HistoryDatabase, offset: int) -> None:
        for index in range(20):
            database.insert_measurement(
                measurement(now + timedelta(microseconds=offset + index))
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(write_many, first, 0),
            executor.submit(write_many, second, 100),
        ]
        for future in futures:
            future.result()

    assert len(first.query_measurements(now - timedelta(seconds=1))) == 40


def test_process_events_are_stored_read_and_masked(database) -> None:
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])

    rows = database.query_process_events(now - timedelta(seconds=1))

    assert len(rows) == 1
    assert rows[0]["event_type"] == "process_started"
    assert rows[0]["pid"] == 77
    assert rows[0]["create_time"] == pytest.approx(now.timestamp() - 10)
    assert rows[0]["command_line"] == "python app.py --token ***"


def test_version_one_database_is_upgraded_to_process_events(tmp_path) -> None:
    path = tmp_path / "version-one.db"
    with sqlite3.connect(path) as connection:
        HistoryDatabase._migrate_to_v1(connection)
        connection.execute("PRAGMA user_version = 1")

    database = HistoryDatabase(path)
    database.initialize()

    with sqlite3.connect(path) as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = 'process_events'"
        ).fetchone()
    assert database.schema_version() == 5
    assert table == ("process_events",)


def test_version_two_upgrade_preserves_existing_measurements(tmp_path) -> None:
    path = tmp_path / "version-two.db"
    now = datetime.now(timezone.utc)
    with sqlite3.connect(path) as connection:
        HistoryDatabase._migrate_to_v1(connection)
        HistoryDatabase._migrate_to_v2(connection)
        connection.execute("PRAGMA user_version = 2")
    database = HistoryDatabase(path)
    database.insert_measurement(measurement(now))
    database.initialize()
    assert len(database.query_measurements(now - timedelta(seconds=1))) == 1
    assert database.schema_version() == 5


def test_version_three_upgrade_preserves_network_data(tmp_path) -> None:
    path = tmp_path / "version-three.db"
    with sqlite3.connect(path) as connection:
        HistoryDatabase._migrate_to_v1(connection)
        HistoryDatabase._migrate_to_v2(connection)
        HistoryDatabase._migrate_to_v3(connection)
        connection.execute(
            """
            INSERT INTO network_events (
                timestamp, event_type, protocol, process_name, pid,
                local_ip, local_port, remote_ip, remote_port,
                address_scope, description, details_json
            ) VALUES (
                '2026-07-19T10:00:00Z', 'Yeni Uzak Hedef', 'TCP',
                'test.exe', '42', '10.0.0.2', '50000', '8.8.8.8', '443',
                'Genel / public', 'test', '{}'
            )
            """
        )
        connection.execute("PRAGMA user_version = 3")

    database = HistoryDatabase(path)
    database.initialize()

    with sqlite3.connect(path) as connection:
        old_count = connection.execute(
            "SELECT COUNT(*) FROM network_events"
        ).fetchone()[0]
        alert_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        ).fetchone()
    assert database.schema_version() == 5
    assert old_count == 1
    assert alert_table == ("alerts",)
