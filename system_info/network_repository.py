"""SQLite repository for network baselines, events, and findings."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import (
    NETWORK_RULE_MANY_TARGETS_COUNT,
    NETWORK_RULE_MANY_TARGETS_SECONDS,
    NETWORK_RULE_NEW_PROCESS_SECONDS,
    REMOTE_ENDPOINT_RESEEN_DAYS,
)
from .database import HistoryDatabase, to_db_timestamp
from .listener_tracker import listener_key
from .i18n import canonical_enum
from .network_models import NetworkSnapshot
from .network_rules import (
    listener_findings,
    many_targets_finding,
    public_endpoint_findings,
)


class NetworkRepository:
    def __init__(self, database: HistoryDatabase) -> None:
        self.database = database

    def process_snapshot(
        self,
        snapshot: NetworkSnapshot,
        listener_events: list[dict[str, Any]],
        connection_events: list[dict[str, Any]] | None = None,
        baseline_only: bool = False,
    ) -> dict[str, int]:
        timestamp = to_db_timestamp(snapshot.captured_at)
        finding_count = 0
        event_count = 0
        with self.database._connection() as connection, connection:
            connection.execute("UPDATE listening_port_baseline SET is_active = 0")
            known_listeners: dict[str, tuple[bool, bool]] = {}
            for raw_listener in snapshot.listeners:
                listener = dict(raw_listener)
                listener["address_scope"] = canonical_enum(
                    "address_scope", listener.get("address_scope")
                )
                key = "|".join(listener_key(listener))
                prior = connection.execute(
                    "SELECT is_expected FROM listening_port_baseline "
                    "WHERE identity_key = ?",
                    (key,),
                ).fetchone()
                known_listeners[key] = (prior is not None, bool(prior[0]) if prior else False)
                self._upsert_listener(connection, key, dict(listener), timestamp)

            if not baseline_only:
                for event in connection_events or []:
                    converted = _connection_network_event(event)
                    self._insert_network_event(connection, converted)
                    event_count += 1
                for raw_event in listener_events:
                    event = dict(raw_event)
                    event["event_type"] = canonical_enum(
                        "listener_event", event.get("event_type")
                    )
                    event["address_scope"] = canonical_enum(
                        "address_scope", event.get("address_scope")
                    )
                    key = "|".join(listener_key(event))
                    was_known, expected = known_listeners.get(key, (True, False))
                    self._insert_listener_event(connection, event)
                    self._insert_network_event(connection, _listener_network_event(event))
                    event_count += 1
                    if event["event_type"] == "listener_started":
                        for finding in listener_findings(event, was_known, expected):
                            self._upsert_finding(connection, finding, timestamp)
                            finding_count += 1

            public_by_process: dict[str, list[dict[str, Any]]] = {}
            for raw in snapshot.connections:
                item = dict(raw)
                item["remote_scope"] = canonical_enum(
                    "address_scope", item.get("remote_scope")
                )
                if item.get("remote_ip") in {None, "", "—"} or not isinstance(
                    item.get("remote_port"), int
                ):
                    continue
                is_new, reseen, expected = self._upsert_endpoint(
                    connection, item, timestamp
                )
                self._record_endpoint_observation(
                    connection,
                    item,
                    snapshot.captured_at,
                )
                self._upsert_endpoint_usage(connection, item, timestamp)
                if item.get("remote_scope") == "public":
                    process_key = (
                        f"{item.get('pid')}|{item.get('process_create_time')}"
                    )
                    public_by_process.setdefault(process_key, []).append(item)
                if baseline_only or not (is_new or reseen):
                    continue
                event_type = (
                    "remote_endpoint_new" if is_new else "remote_endpoint_reappeared"
                )
                process_event_id = self._find_related_process_event(
                    connection,
                    item,
                    snapshot.captured_at,
                )
                item["related_process_event_id"] = process_event_id
                self._insert_network_event(
                    connection, _endpoint_network_event(item, timestamp, event_type)
                )
                event_count += 1
                created = item.get("process_create_time")
                recent = process_event_id is not None or (
                    isinstance(created, (int, float))
                    and 0 <= snapshot.captured_at.timestamp() - float(created)
                    <= NETWORK_RULE_NEW_PROCESS_SECONDS
                )
                for finding in public_endpoint_findings(
                    item, is_new=is_new, process_is_recent=recent, is_expected=expected
                ):
                    self._upsert_finding(connection, finding, timestamp)
                    finding_count += 1

            if not baseline_only:
                for process_key, items in public_by_process.items():
                    recent_items = self._recent_public_targets(
                        connection,
                        process_key,
                        items[0],
                        snapshot.captured_at,
                    )
                    finding = many_targets_finding(
                        process_key,
                        recent_items,
                        NETWORK_RULE_MANY_TARGETS_COUNT,
                        NETWORK_RULE_MANY_TARGETS_SECONDS,
                    )
                    if finding:
                        self._upsert_finding(connection, finding, timestamp)
                        finding_count += 1
        return {"events": event_count, "findings": finding_count}

    @staticmethod
    def _find_related_process_event(
        connection: Any,
        item: dict[str, Any],
        captured_at: datetime,
    ) -> int | None:
        cutoff = to_db_timestamp(
            captured_at - timedelta(seconds=NETWORK_RULE_NEW_PROCESS_SECONDS)
        )
        timestamp = to_db_timestamp(captured_at)
        created = item.get("process_create_time")
        parameters: list[Any] = [
            str(item.get("pid", "—")),
            cutoff,
            timestamp,
        ]
        if isinstance(created, (int, float)):
            parameters.append(float(created))
            query = """
                SELECT id FROM process_events
                WHERE CAST(pid AS TEXT)=?
                  AND event_type='process_started'
                  AND timestamp BETWEEN ? AND ?
                  AND ABS(create_time - ?) < 0.01
                ORDER BY timestamp DESC LIMIT 1
            """
        else:
            query = """
                SELECT id FROM process_events
                WHERE CAST(pid AS TEXT)=?
                  AND event_type='process_started'
                  AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC LIMIT 1
            """
        row = connection.execute(query, parameters).fetchone()
        return int(row["id"]) if row else None

    @staticmethod
    def _recent_public_targets(
        connection: Any,
        process_key: str,
        sample: dict[str, Any],
        captured_at: datetime,
    ) -> list[dict[str, Any]]:
        pid, _, created_text = process_key.partition("|")
        cutoff = to_db_timestamp(
            captured_at - timedelta(seconds=NETWORK_RULE_MANY_TARGETS_SECONDS)
        )
        try:
            created = float(created_text)
        except ValueError:
            created = -1.0
        rows = connection.execute(
            """
            SELECT r.protocol, r.remote_ip, r.remote_port, r.address_scope
            FROM endpoint_process_usage u
            JOIN remote_endpoints r ON r.id=u.endpoint_id
            WHERE u.pid=? AND u.process_create_time=?
              AND u.last_seen>=? AND r.address_scope='public'
            """,
            (pid, created, cutoff),
        ).fetchall()
        return [{**sample, **dict(row)} for row in rows]

    @staticmethod
    def _upsert_listener(
        connection: Any, key: str, item: dict[str, Any], timestamp: str
    ) -> None:
        connection.execute(
            """
            INSERT INTO listening_port_baseline (
                identity_key, protocol, address_family, local_ip, local_port,
                address_scope, pid, process_create_time, process_name,
                process_path, username, parent_pid, parent_process_name,
                command_line, first_seen, last_seen, seen_count, is_active,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?)
            ON CONFLICT(identity_key) DO UPDATE SET
                last_seen=excluded.last_seen,
                seen_count=listening_port_baseline.seen_count + 1,
                is_active=1, updated_at=excluded.updated_at,
                process_name=excluded.process_name,
                process_path=excluded.process_path,
                username=excluded.username,
                command_line=excluded.command_line
            """,
            (
                key,
                item["protocol"],
                item["address_family"],
                item["local_ip"],
                int(item["local_port"]),
                item["address_scope"],
                str(item.get("pid", "—")),
                item.get("process_create_time"),
                item.get("process_name", "Bilinmiyor"),
                item.get("process_path", "Bilinmiyor"),
                item.get("username", "Bilinmiyor"),
                int(item.get("parent_pid", 0)),
                item.get("parent_process_name", "Bilinmiyor"),
                item.get("command_line", "Bilinmiyor"),
                timestamp,
                timestamp,
                timestamp,
            ),
        )

    @staticmethod
    def _insert_listener_event(connection: Any, event: dict[str, Any]) -> None:
        connection.execute(
            """
            INSERT INTO listening_port_events (
                timestamp, event_type, protocol, address_family, local_ip,
                local_port, address_scope, pid, process_create_time,
                process_name, process_path, username, parent_pid,
                parent_process_name, first_seen, last_seen, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"], event["event_type"], event["protocol"],
                event["address_family"], event["local_ip"], int(event["local_port"]),
                event["address_scope"], str(event.get("pid", "—")),
                event.get("process_create_time"), event.get("process_name", "Bilinmiyor"),
                event.get("process_path", "Bilinmiyor"), event.get("username", "Bilinmiyor"),
                int(event.get("parent_pid", 0)),
                event.get("parent_process_name", "Bilinmiyor"),
                event.get("first_seen", event["timestamp"]),
                event.get("last_seen", event["timestamp"]),
                json.dumps(event, ensure_ascii=False, default=str),
            ),
        )

    def _upsert_endpoint(
        self, connection: Any, item: dict[str, Any], timestamp: str
    ) -> tuple[bool, bool, bool]:
        prior = connection.execute(
            "SELECT id, last_seen, is_expected FROM remote_endpoints "
            "WHERE protocol=? AND remote_ip=? AND remote_port=?",
            (item["protocol"], item["remote_ip"], int(item["remote_port"])),
        ).fetchone()
        is_new = prior is None
        reseen = False
        expected = bool(prior["is_expected"]) if prior else False
        if prior:
            cutoff = datetime.now(timezone.utc) - timedelta(
                days=REMOTE_ENDPOINT_RESEEN_DAYS
            )
            try:
                last = datetime.fromisoformat(
                    str(prior["last_seen"]).replace("Z", "+00:00")
                )
                reseen = last < cutoff
            except ValueError:
                reseen = False
        event_type = (
            "remote_endpoint_new"
            if is_new
            else "remote_endpoint_reappeared"
            if reseen
            else "seen"
        )
        connection.execute(
            """
            INSERT INTO remote_endpoints (
                protocol, remote_ip, remote_port, address_family, address_scope,
                first_seen, last_seen, seen_count, last_process_name, last_pid,
                last_process_create_time, last_status, is_first_seen,
                last_event_type, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(protocol, remote_ip, remote_port) DO UPDATE SET
                last_seen=excluded.last_seen,
                seen_count=remote_endpoints.seen_count + 1,
                last_process_name=excluded.last_process_name,
                last_pid=excluded.last_pid,
                last_process_create_time=excluded.last_process_create_time,
                last_status=excluded.last_status,
                is_first_seen=0,
                last_event_type=excluded.last_event_type,
                updated_at=excluded.updated_at
            """,
            (
                item["protocol"], item["remote_ip"], int(item["remote_port"]),
                item["address_family"], item.get("remote_scope", "Belirsiz"),
                timestamp, timestamp, item.get("process_name", "Bilinmiyor"),
                str(item.get("pid", "—")), item.get("process_create_time"),
                canonical_enum("network_status", item.get("status", "unknown")),
                1 if is_new else 0,
                event_type, timestamp,
            ),
        )
        return is_new, reseen, expected

    @staticmethod
    def _record_endpoint_observation(
        connection: Any,
        item: dict[str, Any],
        captured_at: datetime,
    ) -> None:
        endpoint_id = connection.execute(
            "SELECT id FROM remote_endpoints WHERE protocol=? AND remote_ip=? "
            "AND remote_port=?",
            (item["protocol"], item["remote_ip"], int(item["remote_port"])),
        ).fetchone()[0]
        observed_hour = to_db_timestamp(
            captured_at.astimezone(timezone.utc).replace(
                minute=0,
                second=0,
                microsecond=0,
            )
        )
        connection.execute(
            """
            INSERT INTO endpoint_hourly_observations (
                endpoint_id, observed_hour, observation_count
            ) VALUES (?, ?, 1)
            ON CONFLICT(endpoint_id, observed_hour) DO UPDATE SET
                observation_count=endpoint_hourly_observations.observation_count + 1
            """,
            (endpoint_id, observed_hour),
        )

    @staticmethod
    def _upsert_endpoint_usage(
        connection: Any, item: dict[str, Any], timestamp: str
    ) -> None:
        endpoint_id = connection.execute(
            "SELECT id FROM remote_endpoints WHERE protocol=? AND remote_ip=? "
            "AND remote_port=?",
            (item["protocol"], item["remote_ip"], int(item["remote_port"])),
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO endpoint_process_usage (
                endpoint_id, pid, process_create_time, process_name,
                first_seen, last_seen, connection_count
            ) VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_id, pid, process_create_time) DO UPDATE SET
                last_seen=excluded.last_seen,
                connection_count=endpoint_process_usage.connection_count + 1,
                process_name=excluded.process_name
            """,
            (
                endpoint_id, str(item.get("pid", "—")),
                (
                    item.get("process_create_time")
                    if isinstance(item.get("process_create_time"), (int, float))
                    else -1
                ),
                item.get("process_name", "Bilinmiyor"), timestamp, timestamp,
            ),
        )

    @staticmethod
    def _insert_network_event(connection: Any, event: dict[str, Any]) -> None:
        connection.execute(
            """
            INSERT INTO network_events (
                timestamp, event_type, protocol, process_name, pid,
                local_ip, local_port, remote_ip, remote_port,
                address_scope, description, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"], event["event_type"], event["protocol"],
                event["process_name"], str(event["pid"]), event["local_ip"],
                str(event["local_port"]), event["remote_ip"],
                str(event["remote_port"]), event["address_scope"],
                event["description"],
                json.dumps(event, ensure_ascii=False, default=str),
            ),
        )

    @staticmethod
    def _upsert_finding(
        connection: Any, finding: dict[str, Any], timestamp: str
    ) -> None:
        connection.execute(
            """
            INSERT INTO network_findings (
                dedup_key, timestamp, rule_id, severity, title, description,
                process_name, pid, process_create_time, local_address,
                remote_address, first_seen, last_seen, status,
                evidence_json, repeat_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 1)
            ON CONFLICT(dedup_key) DO UPDATE SET
                timestamp=excluded.timestamp, last_seen=excluded.last_seen,
                repeat_count=network_findings.repeat_count + 1,
                evidence_json=excluded.evidence_json
            """,
            (
                finding["dedup_key"], timestamp, finding["rule_id"],
                finding["severity"], finding["title"], finding["description"],
                finding["process_name"], str(finding["pid"]),
                finding.get("process_create_time"), finding["local_address"],
                finding["remote_address"], timestamp, timestamp,
                finding["evidence_json"],
            ),
        )

    def query_dashboard(self, limit: int = 2000) -> dict[str, Any]:
        since_24h = to_db_timestamp(datetime.now(timezone.utc) - timedelta(hours=24))
        with self.database._connection() as connection:
            listeners = [
                dict(row) for row in connection.execute(
                    "SELECT * FROM listening_port_baseline WHERE is_active=1 "
                    "ORDER BY last_seen DESC LIMIT ?", (limit,)
                ).fetchall()
            ]
            endpoints = [
                dict(row) for row in connection.execute(
                    """
                    SELECT r.*,
                           d.hostname,
                           COALESCE((
                               SELECT SUM(o.observation_count)
                               FROM endpoint_hourly_observations o
                               WHERE o.endpoint_id=r.id AND o.observed_hour>=?
                           ), 0) AS seen_count_24h,
                           COUNT(DISTINCT u.pid || ':' || COALESCE(u.process_create_time, '')) AS process_count,
                           GROUP_CONCAT(DISTINCT u.process_name) AS process_names,
                           GROUP_CONCAT(
                               u.process_name || ' (PID ' || u.pid || '): '
                               || u.connection_count
                           ) AS process_usage_summary
                    FROM remote_endpoints r
                    LEFT JOIN endpoint_process_usage u ON u.endpoint_id=r.id
                    LEFT JOIN dns_cache d ON d.ip_address=r.remote_ip
                    GROUP BY r.id ORDER BY r.last_seen DESC LIMIT ?
                    """, (since_24h, limit)
                ).fetchall()
            ]
            events = [
                dict(row) for row in connection.execute(
                    "SELECT * FROM network_events ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]
            findings = [
                dict(row) for row in connection.execute(
                    "SELECT * FROM network_findings ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]
            event_24h = connection.execute(
                "SELECT COUNT(*) FROM network_events WHERE timestamp>=?", (since_24h,)
            ).fetchone()[0]
        return {
            "listeners": listeners,
            "endpoints": endpoints,
            "events": events,
            "findings": findings,
            "event_count_24h": int(event_24h),
        }

    def set_finding_status(self, finding_id: int, status: str) -> None:
        status = canonical_enum("finding_status", status)
        if status not in {"open", "reviewed", "ignored"}:
            raise ValueError("Invalid finding status")
        with self.database._connection() as connection, connection:
            connection.execute(
                "UPDATE network_findings SET status=? WHERE id=?",
                (status, int(finding_id)),
            )

    def set_expected(
        self, kind: str, record_id: str | int, expected: bool, note: str = ""
    ) -> None:
        if kind == "listener":
            query = (
                "UPDATE listening_port_baseline "
                "SET is_expected=?, user_note=?, updated_at=? WHERE identity_key=?"
            )
        elif kind == "endpoint":
            query = (
                "UPDATE remote_endpoints "
                "SET is_expected=?, user_note=?, updated_at=? WHERE id=?"
            )
        else:
            raise ValueError("Invalid baseline type")
        with self.database._connection() as connection, connection:
            connection.execute(
                query,
                (1 if expected else 0, note, to_db_timestamp(), record_id),
            )


def _listener_network_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event["timestamp"],
        "event_type": event["event_type"],
        "protocol": event["protocol"],
        "process_name": event.get("process_name", "Bilinmiyor"),
        "pid": event.get("pid", "—"),
        "local_ip": event["local_ip"],
        "local_port": event["local_port"],
        "remote_ip": "—",
        "remote_port": "—",
        "address_scope": event["address_scope"],
        "description": (
            f"{event['process_name']} changed listener state on "
            f"{event['local_ip']}:{event['local_port']}."
        ),
        **event,
    }


def _endpoint_network_event(
    item: dict[str, Any], timestamp: str, event_type: str
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "protocol": item["protocol"],
        "process_name": item.get("process_name", "Bilinmiyor"),
        "pid": item.get("pid", "—"),
        "local_ip": item["local_ip"],
        "local_port": item["local_port"],
        "remote_ip": item["remote_ip"],
        "remote_port": item["remote_port"],
        "address_scope": item.get("remote_scope", "Belirsiz"),
        "description": (
            f"{item['process_name']} communicated with remote endpoint "
            f"{item['remote_ip']}:{item['remote_port']}."
        ),
        **item,
    }


def _connection_network_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = (
        "connection_opened"
        if event["event_type"] == "connection_opened"
        else "connection_closed"
    )
    return {
        **event,
        "timestamp": event["timestamp"],
        "event_type": event_type,
        "protocol": event["protocol"],
        "process_name": event.get("process_name", "Bilinmiyor"),
        "pid": event.get("pid", "—"),
        "local_ip": event.get("local_ip", "—"),
        "local_port": event.get("local_port", "—"),
        "remote_ip": event.get("remote_ip", "—"),
        "remote_port": event.get("remote_port", "—"),
        "address_scope": event.get("address_scope", "Belirsiz"),
        "description": f"Connection state changed for {event['process_name']}.",
    }
