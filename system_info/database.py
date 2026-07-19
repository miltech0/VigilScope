"""Persistent SQLite storage for history, baselines, alerts, and cases."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import (
    CONNECTION_EVENT_RETENTION_DAYS,
    DNS_CACHE_RETENTION_DAYS,
    ENDPOINT_OBSERVATION_RETENTION_DAYS,
    LISTENING_EVENT_RETENTION_DAYS,
    MEASUREMENT_RETENTION_DAYS,
    NETWORK_EVENT_RETENTION_DAYS,
    PROCESS_EVENT_RETENTION_DAYS,
)
from .process_security import mask_sensitive_command_line
from .filesystem_security import ensure_private_directory, ensure_private_file
from .i18n import canonical_enum

SCHEMA_VERSION = 5


class DatabaseError(RuntimeError):
    """Raised when a storage operation cannot be completed safely."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_db_timestamp(value: datetime | None = None) -> str:
    timestamp = value or utc_now()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _normalize_rule_enums(value: Any, parent_key: str = "") -> bool:
    """Normalize structural rule enum values without translating user prose."""
    changed = False
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if key == "severity" and isinstance(item, str):
                normalized = canonical_enum("severity", item)
                if normalized != item:
                    value[key] = normalized
                    changed = True
            elif key == "address_scope" and isinstance(item, str):
                normalized = canonical_enum("address_scope", item)
                if normalized != item:
                    value[key] = normalized
                    changed = True
            elif key == "value" and parent_key == "address_scope" and isinstance(item, str):
                normalized = canonical_enum("address_scope", item)
                if normalized != item:
                    value[key] = normalized
                    changed = True
            elif _normalize_rule_enums(item, str(value.get("field", key))):
                changed = True
    elif isinstance(value, list):
        for item in value:
            if _normalize_rule_enums(item, parent_key):
                changed = True
    return changed


class HistoryDatabase:
    """Use short-lived connections for thread and multi-window safety."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @contextmanager
    def _connection(self) -> Iterable[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            ensure_private_directory(self.path.parent)
            connection = sqlite3.connect(self.path, timeout=5.0)
            ensure_private_file(self.path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
        except (sqlite3.Error, OSError) as exc:
            raise DatabaseError(f"Database operation failed: {exc}") from exc
        finally:
            if connection is not None:
                connection.close()

    def initialize(self) -> None:
        """Upgrade the schema safely and repeatably."""
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            current_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if current_version > SCHEMA_VERSION:
                raise DatabaseError(
                    f"Unsupported database version: {current_version}"
                )

            with connection:
                if current_version < 1:
                    self._migrate_to_v1(connection)
                if current_version < 2:
                    self._migrate_to_v2(connection)
                if current_version < 3:
                    self._migrate_to_v3(connection)
                if current_version < 4:
                    self._migrate_to_v4(connection)
                if current_version < 5:
                    self._migrate_to_v5(connection)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _migrate_to_v1(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS system_measurements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                ram_percent REAL NOT NULL,
                ram_used_bytes INTEGER NOT NULL,
                disk_percent REAL NOT NULL,
                active_connections INTEGER NOT NULL,
                net_bytes_sent INTEGER NOT NULL,
                net_bytes_recv INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_system_measurements_timestamp
            ON system_measurements(timestamp)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS connection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                protocol TEXT NOT NULL,
                pid TEXT NOT NULL,
                process_name TEXT NOT NULL,
                local_ip TEXT NOT NULL,
                local_port TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                remote_port TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_connection_events_timestamp
            ON connection_events(timestamp)
            """
        )

    @staticmethod
    def _migrate_to_v2(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                pid INTEGER NOT NULL,
                create_time REAL,
                process_name TEXT NOT NULL,
                parent_pid INTEGER NOT NULL,
                parent_name TEXT NOT NULL,
                username TEXT NOT NULL,
                exe TEXT NOT NULL,
                command_line TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_process_events_timestamp
            ON process_events(timestamp)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_process_events_identity
            ON process_events(pid, create_time)
            """
        )

    @staticmethod
    def _migrate_to_v3(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS listening_port_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                protocol TEXT NOT NULL, address_family TEXT NOT NULL,
                local_ip TEXT NOT NULL, local_port INTEGER NOT NULL,
                address_scope TEXT NOT NULL, pid TEXT NOT NULL,
                process_create_time REAL, process_name TEXT NOT NULL,
                process_path TEXT NOT NULL, username TEXT NOT NULL,
                parent_pid INTEGER NOT NULL, parent_process_name TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_listener_events_time
                ON listening_port_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_listener_events_type
                ON listening_port_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_listener_events_port
                ON listening_port_events(local_port);

            CREATE TABLE IF NOT EXISTS listening_port_baseline (
                identity_key TEXT PRIMARY KEY,
                protocol TEXT NOT NULL, address_family TEXT NOT NULL,
                local_ip TEXT NOT NULL, local_port INTEGER NOT NULL,
                address_scope TEXT NOT NULL, pid TEXT NOT NULL,
                process_create_time REAL, process_name TEXT NOT NULL,
                process_path TEXT NOT NULL, username TEXT NOT NULL,
                parent_pid INTEGER NOT NULL, parent_process_name TEXT NOT NULL,
                command_line TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_expected INTEGER NOT NULL DEFAULT 0,
                user_note TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_listener_baseline_last
                ON listening_port_baseline(last_seen);
            CREATE INDEX IF NOT EXISTS idx_listener_baseline_process
                ON listening_port_baseline(process_name, pid);

            CREATE TABLE IF NOT EXISTS remote_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT NOT NULL, remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL, address_family TEXT NOT NULL,
                address_scope TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                last_process_name TEXT NOT NULL, last_pid TEXT NOT NULL,
                last_process_create_time REAL, last_status TEXT NOT NULL,
                is_first_seen INTEGER NOT NULL DEFAULT 1,
                last_event_type TEXT NOT NULL DEFAULT 'baseline',
                is_expected INTEGER NOT NULL DEFAULT 0,
                user_note TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                UNIQUE(protocol, remote_ip, remote_port)
            );
            CREATE INDEX IF NOT EXISTS idx_remote_endpoint_ip
                ON remote_endpoints(remote_ip, remote_port);
            CREATE INDEX IF NOT EXISTS idx_remote_endpoint_last
                ON remote_endpoints(last_seen);

            CREATE TABLE IF NOT EXISTS endpoint_process_usage (
                endpoint_id INTEGER NOT NULL REFERENCES remote_endpoints(id)
                    ON DELETE CASCADE,
                pid TEXT NOT NULL, process_create_time REAL NOT NULL DEFAULT -1,
                process_name TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                connection_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(endpoint_id, pid, process_create_time)
            );
            CREATE INDEX IF NOT EXISTS idx_endpoint_usage_process
                ON endpoint_process_usage(process_name, pid);

            CREATE TABLE IF NOT EXISTS endpoint_hourly_observations (
                endpoint_id INTEGER NOT NULL REFERENCES remote_endpoints(id)
                    ON DELETE CASCADE,
                observed_hour TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(endpoint_id, observed_hour)
            );
            CREATE INDEX IF NOT EXISTS idx_endpoint_observation_hour
                ON endpoint_hourly_observations(observed_hour);

            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                protocol TEXT NOT NULL, process_name TEXT NOT NULL,
                pid TEXT NOT NULL, local_ip TEXT NOT NULL,
                local_port TEXT NOT NULL, remote_ip TEXT NOT NULL,
                remote_port TEXT NOT NULL, address_scope TEXT NOT NULL,
                description TEXT NOT NULL, details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_network_events_time
                ON network_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_events_type
                ON network_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_network_events_remote
                ON network_events(remote_ip, remote_port);
            CREATE INDEX IF NOT EXISTS idx_network_events_process
                ON network_events(process_name, pid);

            CREATE TABLE IF NOT EXISTS network_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dedup_key TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL, rule_id TEXT NOT NULL,
                severity TEXT NOT NULL, title TEXT NOT NULL,
                description TEXT NOT NULL, process_name TEXT NOT NULL,
                pid TEXT NOT NULL, process_create_time REAL,
                local_address TEXT NOT NULL, remote_address TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                evidence_json TEXT NOT NULL,
                repeat_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_findings_time
                ON network_findings(timestamp);
            CREATE INDEX IF NOT EXISTS idx_findings_status
                ON network_findings(status, severity, rule_id);

            CREATE TABLE IF NOT EXISTS dns_cache (
                ip_address TEXT PRIMARY KEY, hostname TEXT NOT NULL,
                resolved_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_expiry ON dns_cache(expires_at);
            """
        )

    @staticmethod
    def _migrate_to_v4(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS detection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                username TEXT NOT NULL,
                process_name TEXT NOT NULL,
                pid TEXT NOT NULL,
                process_create_time REAL,
                parent_pid TEXT NOT NULL,
                parent_process_name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                masked_command_line TEXT NOT NULL,
                protocol TEXT NOT NULL,
                local_ip TEXT NOT NULL,
                local_port TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                remote_port TEXT NOT NULL,
                address_scope TEXT NOT NULL,
                source_table TEXT NOT NULL,
                source_record_id INTEGER NOT NULL,
                additional_data_json TEXT NOT NULL,
                UNIQUE(source_table, source_record_id)
            );
            CREATE INDEX IF NOT EXISTS idx_detection_events_time
                ON detection_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_detection_events_type
                ON detection_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_detection_events_process
                ON detection_events(process_name, pid, process_create_time);
            CREATE INDEX IF NOT EXISTS idx_detection_events_remote
                ON detection_events(remote_ip, remote_port);

            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                version TEXT NOT NULL,
                content_json TEXT NOT NULL,
                is_builtin INTEGER NOT NULL DEFAULT 0,
                last_match_at TEXT,
                match_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled
                ON detection_rules(enabled, severity, category);

            CREATE TABLE IF NOT EXISTS detection_checkpoints (
                source_table TEXT PRIMARY KEY,
                last_record_id INTEGER NOT NULL DEFAULT 0,
                initialized INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                hostname TEXT NOT NULL,
                username TEXT NOT NULL,
                process_name TEXT NOT NULL,
                pid TEXT NOT NULL,
                process_create_time REAL,
                parent_process_name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                masked_command_line TEXT NOT NULL,
                local_address TEXT NOT NULL,
                remote_address TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                mitre_tactics TEXT NOT NULL,
                mitre_techniques TEXT NOT NULL,
                deduplication_key TEXT NOT NULL UNIQUE,
                evidence_summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                expected_behavior INTEGER NOT NULL DEFAULT 0,
                expected_note TEXT NOT NULL DEFAULT '',
                case_id INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity_status
                ON alerts(severity, status);
            CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_first_last
                ON alerts(first_seen, last_seen);
            CREATE INDEX IF NOT EXISTS idx_alerts_process
                ON alerts(process_name, pid);
            CREATE INDEX IF NOT EXISTS idx_alerts_remote ON alerts(remote_ip);

            CREATE TABLE IF NOT EXISTS alert_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                source_type TEXT NOT NULL,
                source_table TEXT NOT NULL,
                source_record_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                process_identity TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                UNIQUE(alert_id, source_table, source_record_id)
            );
            CREATE INDEX IF NOT EXISTS idx_alert_evidence_alert_time
                ON alert_evidence(alert_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_alert_evidence_source
                ON alert_evidence(source_table, source_record_id);

            CREATE TABLE IF NOT EXISTS alert_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                author TEXT NOT NULL,
                note_text TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_notes_alert
                ON alert_notes(alert_id, created_at);

            CREATE TABLE IF NOT EXISTS alert_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                changed_at TEXT NOT NULL,
                old_status TEXT NOT NULL,
                new_status TEXT NOT NULL,
                description TEXT NOT NULL,
                user_note TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_status_alert
                ON alert_status_history(alert_id, changed_at);

            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                first_event_at TEXT NOT NULL,
                last_event_at TEXT NOT NULL,
                hostname TEXT NOT NULL,
                summary TEXT NOT NULL,
                conclusion TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_cases_status
                ON cases(status, severity, updated_at);

            CREATE TABLE IF NOT EXISTS case_alerts (
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                added_at TEXT NOT NULL,
                PRIMARY KEY(case_id, alert_id)
            );
            CREATE INDEX IF NOT EXISTS idx_case_alerts_alert
                ON case_alerts(alert_id);

            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                author TEXT NOT NULL,
                note_text TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_case_notes_case
                ON case_notes(case_id, created_at);

            CREATE TABLE IF NOT EXISTS suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                reason TEXT NOT NULL,
                match_conditions_json TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 0,
                last_matched_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_suppressions_enabled
                ON suppressions(enabled, expires_at);
            """
        )

    @staticmethod
    def _migrate_to_v5(connection: sqlite3.Connection) -> None:
        """Normalize language-dependent enum values while preserving free text."""
        mappings = (
            ("network_findings", "severity", "severity"),
            ("network_findings", "status", "finding_status"),
            ("alerts", "severity", "severity"),
            ("alerts", "status", "alert_status"),
            ("cases", "severity", "severity"),
            ("cases", "status", "case_status"),
            ("detection_rules", "severity", "severity"),
            ("alert_status_history", "old_status", "alert_status"),
            ("alert_status_history", "new_status", "alert_status"),
            ("process_events", "event_type", "process_event"),
            ("connection_events", "event_type", "connection_event"),
            ("listening_port_events", "event_type", "listener_event"),
            ("network_events", "event_type", "network_event"),
            ("listening_port_events", "address_scope", "address_scope"),
            ("listening_port_baseline", "address_scope", "address_scope"),
            ("remote_endpoints", "address_scope", "address_scope"),
            ("network_events", "address_scope", "address_scope"),
            ("detection_events", "address_scope", "address_scope"),
            ("remote_endpoints", "last_event_type", "network_event"),
            ("connection_events", "status", "network_status"),
            ("remote_endpoints", "last_status", "network_status"),
        )
        for table, column, domain in mappings:
            select_sql = (
                # Identifiers come from the fixed migration mapping.
                f"SELECT rowid AS record_rowid, {column} FROM {table}"  # nosec B608
            )
            rows = connection.execute(select_sql).fetchall()
            for row in rows:
                old_value = row[column]
                new_value = canonical_enum(domain, old_value)
                if new_value != old_value and new_value != "unknown":
                    update_sql = (
                        # Identifiers come from the fixed migration mapping.
                        f"UPDATE {table} SET {column}=? WHERE rowid=?"  # nosec B608
                    )
                    connection.execute(
                        update_sql,
                        (new_value, row["record_rowid"]),
                    )

        rule_rows = connection.execute(
            "SELECT rule_id, content_json FROM detection_rules"
        ).fetchall()
        for row in rule_rows:
            try:
                content = json.loads(row["content_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(content, dict):
                continue
            if _normalize_rule_enums(content):
                connection.execute(
                    "UPDATE detection_rules SET content_json=? WHERE rule_id=?",
                    (
                        json.dumps(content, ensure_ascii=False, separators=(",", ":")),
                        row["rule_id"],
                    ),
                )

    def schema_version(self) -> int:
        with self._connection() as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def insert_measurement(self, measurement: Mapping[str, Any]) -> None:
        values = (
            str(measurement.get("timestamp") or to_db_timestamp()),
            float(measurement["cpu_percent"]),
            float(measurement["ram_percent"]),
            int(measurement["ram_used_bytes"]),
            float(measurement["disk_percent"]),
            int(measurement["active_connections"]),
            int(measurement["net_bytes_sent"]),
            int(measurement["net_bytes_recv"]),
        )
        with self._connection() as connection, connection:
            connection.execute(
                """
                INSERT INTO system_measurements (
                    timestamp, cpu_percent, ram_percent, ram_used_bytes,
                    disk_percent, active_connections, net_bytes_sent,
                    net_bytes_recv
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )

    def insert_connection_events(
        self, events: Iterable[Mapping[str, Any]]
    ) -> int:
        rows = [
            (
                str(event.get("timestamp") or to_db_timestamp()),
                canonical_enum("connection_event", event["event_type"]),
                str(event["protocol"]),
                str(event["pid"]),
                str(event["process_name"]),
                str(event["local_ip"]),
                str(event["local_port"]),
                str(event["remote_ip"]),
                str(event["remote_port"]),
                canonical_enum("network_status", event["status"]),
            )
            for event in events
        ]
        if not rows:
            return 0

        with self._connection() as connection, connection:
            connection.executemany(
                """
                INSERT INTO connection_events (
                    timestamp, event_type, protocol, pid, process_name,
                    local_ip, local_port, remote_ip, remote_port, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def insert_process_events(self, events: Iterable[Mapping[str, Any]]) -> int:
        rows = [
            (
                str(event.get("timestamp") or to_db_timestamp()),
                canonical_enum("process_event", event["event_type"]),
                int(event["pid"]),
                (
                    float(event["create_time"])
                    if isinstance(event.get("create_time"), (int, float))
                    else None
                ),
                str(event["process_name"]),
                int(event.get("parent_pid", 0)),
                str(event.get("parent_name", "Bilinmiyor")),
                str(event.get("username", "Bilinmiyor")),
                str(event.get("exe", "Bilinmiyor")),
                mask_sensitive_command_line(event.get("command_line")),
                str(event.get("first_seen") or event.get("timestamp")),
                str(event.get("last_seen") or event.get("timestamp")),
            )
            for event in events
        ]
        if not rows:
            return 0

        with self._connection() as connection, connection:
            connection.executemany(
                """
                INSERT INTO process_events (
                    timestamp, event_type, pid, create_time, process_name,
                    parent_pid, parent_name, username, exe, command_line,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def query_measurements(
        self, since: datetime, until: datetime | None = None
    ) -> list[dict[str, Any]]:
        parameters: list[str] = [to_db_timestamp(since)]
        where = "timestamp >= ?"
        if until is not None:
            where += " AND timestamp <= ?"
            parameters.append(to_db_timestamp(until))

        query = f"""
            SELECT timestamp, cpu_percent, ram_percent, ram_used_bytes,
                   disk_percent, active_connections, net_bytes_sent,
                   net_bytes_recv
            FROM system_measurements
            WHERE {where}
            ORDER BY timestamp ASC
        """  # nosec B608
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def query_connection_events(
        self,
        since: datetime,
        until: datetime | None = None,
        process_query: str = "",
        event_type: str = "",
        protocol: str = "",
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["timestamp >= ?"]
        parameters: list[str] = [to_db_timestamp(since)]
        if until is not None:
            clauses.append("timestamp <= ?")
            parameters.append(to_db_timestamp(until))
        if process_query.strip():
            clauses.append("LOWER(process_name) LIKE ?")
            parameters.append(f"%{process_query.strip().lower()}%")
        if event_type.strip() and event_type != "Tümü":
            clauses.append("event_type = ?")
            parameters.append(event_type)
        if protocol.strip() and protocol != "Tümü":
            clauses.append("protocol = ?")
            parameters.append(protocol)

        limit_clause = ""
        if limit is not None:
            limit_clause = " LIMIT ?"
            parameters.append(max(0, int(limit)))

        query = f"""
            SELECT timestamp, event_type, protocol, pid, process_name,
                   local_ip, local_port, remote_ip, remote_port, status
            FROM connection_events
            WHERE {" AND ".join(clauses)}
            ORDER BY timestamp DESC
            {limit_clause}
        """  # nosec B608
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def query_process_events(
        self,
        since: datetime,
        until: datetime | None = None,
        process_query: str = "",
        event_type: str = "",
        username_query: str = "",
        path_query: str = "",
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["timestamp >= ?"]
        parameters: list[Any] = [to_db_timestamp(since)]
        if until is not None:
            clauses.append("timestamp <= ?")
            parameters.append(to_db_timestamp(until))
        if process_query.strip():
            clauses.append("LOWER(process_name) LIKE ?")
            parameters.append(f"%{process_query.strip().lower()}%")
        if event_type.strip() and event_type != "Tümü":
            clauses.append("event_type = ?")
            parameters.append(event_type)
        if username_query.strip():
            clauses.append("LOWER(username) LIKE ?")
            parameters.append(f"%{username_query.strip().lower()}%")
        if path_query.strip():
            clauses.append("LOWER(exe) LIKE ?")
            parameters.append(f"%{path_query.strip().lower()}%")

        limit_clause = ""
        if limit is not None:
            limit_clause = " LIMIT ?"
            parameters.append(max(0, int(limit)))

        query = f"""
            SELECT timestamp, event_type, pid, create_time, process_name,
                   parent_pid, parent_name, username, exe, command_line,
                   first_seen, last_seen
            FROM process_events
            WHERE {" AND ".join(clauses)}
            ORDER BY timestamp DESC
            {limit_clause}
        """  # nosec B608
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def cleanup_old_records(
        self,
        now: datetime | None = None,
        measurement_days: int = MEASUREMENT_RETENTION_DAYS,
        event_days: int = CONNECTION_EVENT_RETENTION_DAYS,
        process_event_days: int = PROCESS_EVENT_RETENTION_DAYS,
        listening_event_days: int = LISTENING_EVENT_RETENTION_DAYS,
        network_event_days: int = NETWORK_EVENT_RETENTION_DAYS,
        dns_cache_days: int = DNS_CACHE_RETENTION_DAYS,
        endpoint_observation_days: int = ENDPOINT_OBSERVATION_RETENTION_DAYS,
    ) -> dict[str, int]:
        current = now or utc_now()
        measurement_cutoff = to_db_timestamp(current - timedelta(days=measurement_days))
        event_cutoff = to_db_timestamp(current - timedelta(days=event_days))
        process_event_cutoff = to_db_timestamp(
            current - timedelta(days=process_event_days)
        )
        listener_cutoff = to_db_timestamp(
            current - timedelta(days=listening_event_days)
        )
        network_cutoff = to_db_timestamp(
            current - timedelta(days=network_event_days)
        )
        dns_cutoff = to_db_timestamp(current - timedelta(days=dns_cache_days))
        endpoint_observation_cutoff = to_db_timestamp(
            current - timedelta(days=endpoint_observation_days)
        )

        with self._connection() as connection, connection:
            measurement_cursor = connection.execute(
                "DELETE FROM system_measurements WHERE timestamp < ?",
                (measurement_cutoff,),
            )
            event_cursor = connection.execute(
                "DELETE FROM connection_events WHERE timestamp < ?",
                (event_cutoff,),
            )
            process_event_cursor = connection.execute(
                "DELETE FROM process_events WHERE timestamp < ?",
                (process_event_cutoff,),
            )
            listener_cursor = connection.execute(
                "DELETE FROM listening_port_events WHERE timestamp < ?",
                (listener_cutoff,),
            )
            network_cursor = connection.execute(
                "DELETE FROM network_events WHERE timestamp < ?",
                (network_cutoff,),
            )
            dns_cursor = connection.execute(
                "DELETE FROM dns_cache WHERE resolved_at < ?",
                (dns_cutoff,),
            )
            endpoint_observation_cursor = connection.execute(
                "DELETE FROM endpoint_hourly_observations WHERE observed_hour < ?",
                (endpoint_observation_cutoff,),
            )
        return {
            "measurements": max(measurement_cursor.rowcount, 0),
            "events": max(event_cursor.rowcount, 0),
            "process_events": max(process_event_cursor.rowcount, 0),
            "listening_events": max(listener_cursor.rowcount, 0),
            "network_events": max(network_cursor.rowcount, 0),
            "dns_cache": max(dns_cursor.rowcount, 0),
            "endpoint_observations": max(
                endpoint_observation_cursor.rowcount,
                0,
            ),
        }
