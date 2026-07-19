"""Repository for detection events, rules, alerts, evidence, and checkpoints."""

from __future__ import annotations

import getpass
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import DETECTION_BATCH_SIZE, DETECTION_UI_LIMIT
from .database import HistoryDatabase, to_db_timestamp
from .detection_models import (
    ALERT_STATUSES,
    CASE_STATUSES,
    SEVERITIES,
    DetectionRule,
    NormalizedEvent,
)
from .process_security import mask_sensitive_command_line
from .i18n import canonical_enum
from .rule_loader import rule_to_json
from .rule_validator import RuleValidationError, validate_rule

SOURCE_TABLES = (
    "process_events",
    "connection_events",
    "listening_port_events",
    "network_events",
    "network_findings",
)
SOURCE_MAX_ID_QUERIES = {
    "process_events": "SELECT COALESCE(MAX(id), 0) FROM process_events",
    "connection_events": "SELECT COALESCE(MAX(id), 0) FROM connection_events",
    "listening_port_events": "SELECT COALESCE(MAX(id), 0) FROM listening_port_events",
    "network_events": "SELECT COALESCE(MAX(id), 0) FROM network_events",
    "network_findings": "SELECT COALESCE(MAX(id), 0) FROM network_findings",
}
SOURCE_FETCH_QUERIES = {
    "process_events": "SELECT * FROM process_events WHERE id>? ORDER BY id LIMIT ?",
    "connection_events": "SELECT * FROM connection_events WHERE id>? ORDER BY id LIMIT ?",
    "network_findings": "SELECT * FROM network_findings WHERE id>? ORDER BY id LIMIT ?",
}


class AlertRepository:
    def __init__(self, database: HistoryDatabase) -> None:
        self.database = database

    def sync_builtin_rules(self, rules: list[DetectionRule]) -> None:
        now = to_db_timestamp()
        with self.database._connection() as connection, connection:
            for rule in rules:
                connection.execute(
                    """
                    INSERT INTO detection_rules (
                        rule_id, title, description, enabled, severity, category,
                        version, content_json, is_builtin, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(rule_id) DO UPDATE SET
                        title=excluded.title,
                        description=excluded.description,
                        severity=excluded.severity,
                        category=excluded.category,
                        version=excluded.version,
                        content_json=excluded.content_json,
                        is_builtin=1,
                        updated_at=excluded.updated_at
                    """,
                    (
                        rule["id"],
                        rule["title"],
                        rule["description"],
                        1 if rule.get("enabled", True) else 0,
                        rule["severity"],
                        rule["category"],
                        rule.get("version", "1.0"),
                        rule_to_json(rule),
                        now,
                        now,
                    ),
                )

    def list_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        query = (
            "SELECT * FROM detection_rules WHERE enabled=1 ORDER BY rule_id"
            if enabled_only
            else "SELECT * FROM detection_rules ORDER BY rule_id"
        )
        with self.database._connection() as connection:
            rows = connection.execute(query).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                rule = json.loads(item["content_json"])
            except json.JSONDecodeError:
                continue
            rule["enabled"] = bool(item["enabled"])
            rule["_metadata"] = {
                key: item[key]
                for key in (
                    "is_builtin",
                    "last_match_at",
                    "match_count",
                    "created_at",
                    "updated_at",
                )
            }
            result.append(rule)
        return result

    def save_user_rule(self, rule: dict[str, Any]) -> None:
        validated = validate_rule(rule)
        now = to_db_timestamp()
        with self.database._connection() as connection, connection:
            prior = connection.execute(
                "SELECT is_builtin FROM detection_rules WHERE rule_id=?",
                (validated["id"],),
            ).fetchone()
            if prior and prior["is_builtin"]:
                raise RuleValidationError("Built-in rules cannot be edited; only disabled")
            connection.execute(
                """
                INSERT INTO detection_rules (
                    rule_id, title, description, enabled, severity, category,
                    version, content_json, is_builtin, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    title=excluded.title, description=excluded.description,
                    enabled=excluded.enabled, severity=excluded.severity,
                    category=excluded.category, version=excluded.version,
                    content_json=excluded.content_json,
                    updated_at=excluded.updated_at
                """,
                (
                    validated["id"],
                    validated["title"],
                    validated["description"],
                    1 if validated.get("enabled", True) else 0,
                    validated["severity"],
                    validated["category"],
                    validated.get("version", "1.0"),
                    rule_to_json(validated),
                    now,
                    now,
                ),
            )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        with self.database._connection() as connection, connection:
            connection.execute(
                "UPDATE detection_rules SET enabled=?, updated_at=? WHERE rule_id=?",
                (1 if enabled else 0, to_db_timestamp(), rule_id),
            )

    def delete_user_rule(self, rule_id: str) -> None:
        with self.database._connection() as connection, connection:
            row = connection.execute(
                "SELECT is_builtin FROM detection_rules WHERE rule_id=?",
                (rule_id,),
            ).fetchone()
            if row and row["is_builtin"]:
                raise RuleValidationError("Built-in rules cannot be deleted")
            connection.execute(
                "DELETE FROM detection_rules WHERE rule_id=?",
                (rule_id,),
            )

    def initialize_checkpoints(self, baseline_existing: bool = True) -> None:
        now = to_db_timestamp()
        with self.database._connection() as connection, connection:
            for source in SOURCE_TABLES:
                exists = connection.execute(
                    "SELECT 1 FROM detection_checkpoints WHERE source_table=?",
                    (source,),
                ).fetchone()
                if exists:
                    continue
                maximum = (
                    int(
                        connection.execute(SOURCE_MAX_ID_QUERIES[source]).fetchone()[0]
                    )
                    if baseline_existing
                    else 0
                )
                connection.execute(
                    """
                    INSERT INTO detection_checkpoints (
                        source_table, last_record_id, initialized, updated_at
                    ) VALUES (?, ?, 1, ?)
                    """,
                    (source, maximum, now),
                )

    def checkpoint(self, source_table: str) -> int:
        with self.database._connection() as connection:
            row = connection.execute(
                "SELECT last_record_id FROM detection_checkpoints WHERE source_table=?",
                (source_table,),
            ).fetchone()
        return int(row[0]) if row else 0

    def advance_checkpoint(self, source_table: str, record_id: int) -> None:
        with self.database._connection() as connection, connection:
            connection.execute(
                """
                INSERT INTO detection_checkpoints (
                    source_table, last_record_id, initialized, updated_at
                ) VALUES (?, ?, 1, ?)
                ON CONFLICT(source_table) DO UPDATE SET
                    last_record_id=MAX(last_record_id, excluded.last_record_id),
                    initialized=1,
                    updated_at=excluded.updated_at
                """,
                (source_table, int(record_id), to_db_timestamp()),
            )

    def fetch_source_rows(
        self,
        source_table: str,
        after_id: int,
        limit: int = DETECTION_BATCH_SIZE,
    ) -> list[dict[str, Any]]:
        if source_table not in SOURCE_TABLES:
            raise ValueError("Unsupported event source")
        if source_table == "listening_port_events":
            sql = """
                SELECT e.*, COALESCE(b.is_expected, 0) AS is_expected,
                       COALESCE(b.user_note, '') AS user_note
                FROM listening_port_events e
                LEFT JOIN listening_port_baseline b
                  ON b.protocol=e.protocol
                 AND b.address_family=e.address_family
                 AND b.local_ip=e.local_ip
                 AND b.local_port=e.local_port
                 AND b.pid=e.pid
                 AND COALESCE(b.process_create_time, -1)
                     = COALESCE(e.process_create_time, -1)
                WHERE e.id>? ORDER BY e.id LIMIT ?
            """
        elif source_table == "network_events":
            sql = """
                SELECT e.*, COALESCE(r.is_expected, 0) AS is_expected,
                       COALESCE(r.user_note, '') AS user_note
                FROM network_events e
                LEFT JOIN remote_endpoints r
                  ON r.protocol=e.protocol
                 AND r.remote_ip=e.remote_ip
                 AND CAST(r.remote_port AS TEXT)=CAST(e.remote_port AS TEXT)
                WHERE e.id>?
                  AND e.event_type IN (
                      'remote_endpoint_new',
                      'remote_endpoint_reappeared',
                      'Yeni Uzak Hedef',
                      'Uzak Hedef Yeniden Görüldü'
                  )
                ORDER BY e.id LIMIT ?
            """
        else:
            sql = SOURCE_FETCH_QUERIES[source_table]
        with self.database._connection() as connection:
            rows = connection.execute(
                sql,
                (int(after_id), max(1, int(limit))),
            ).fetchall()
        return [dict(row) for row in rows]

    def insert_normalized_event(self, event: NormalizedEvent) -> int:
        with self.database._connection() as connection, connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO detection_events (
                    event_id, event_type, timestamp, hostname, username,
                    process_name, pid, process_create_time, parent_pid,
                    parent_process_name, executable_path, masked_command_line,
                    protocol, local_ip, local_port, remote_ip, remote_port,
                    address_scope, source_table, source_record_id,
                    additional_data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    event["event_type"],
                    event["timestamp"],
                    event["hostname"],
                    event["username"],
                    event["process_name"],
                    event["pid"],
                    event.get("process_create_time"),
                    event["parent_pid"],
                    event["parent_process_name"],
                    event["executable_path"],
                    mask_sensitive_command_line(event["masked_command_line"]),
                    event["protocol"],
                    event["local_ip"],
                    event["local_port"],
                    event["remote_ip"],
                    event["remote_port"],
                    event["address_scope"],
                    event["source_table"],
                    event["source_record_id"],
                    json.dumps(event.get("additional_data", {}), ensure_ascii=False, default=str),
                ),
            )
            row = connection.execute(
                "SELECT id FROM detection_events WHERE event_id=?",
                (event["event_id"],),
            ).fetchone()
        return int(row[0])

    def recent_events(
        self,
        since: datetime,
        limit: int = DETECTION_UI_LIMIT,
        until: datetime | None = None,
    ) -> list[NormalizedEvent]:
        until_value = until or datetime.max.replace(tzinfo=timezone.utc)
        with self.database._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM (
                    SELECT * FROM detection_events
                    WHERE timestamp>=? AND timestamp<=?
                    ORDER BY timestamp DESC, id DESC LIMIT ?
                )
                ORDER BY timestamp ASC, id ASC
                """,
                (
                    to_db_timestamp(since),
                    to_db_timestamp(until_value),
                    max(1, int(limit)),
                ),
            ).fetchall()
        return [self._event_from_row(dict(row)) for row in rows]

    def list_events(
        self,
        since: datetime | None = None,
        limit: int = DETECTION_UI_LIMIT,
    ) -> list[dict[str, Any]]:
        cutoff = since or datetime.min.replace(tzinfo=timezone.utc)
        events = self.recent_events(cutoff, limit)
        return list(reversed(events))

    def active_suppressions(self) -> list[dict[str, Any]]:
        now = to_db_timestamp()
        with self.database._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM suppressions
                WHERE enabled=1 AND (expires_at IS NULL OR expires_at='' OR expires_at>?)
                ORDER BY created_at DESC
                """,
                (now,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["match_conditions"] = json.loads(item["match_conditions_json"])
            except json.JSONDecodeError:
                item["match_conditions"] = {}
            result.append(item)
        return result

    def create_suppression(
        self,
        name: str,
        conditions: dict[str, Any],
        reason: str,
        expires_at: str | None = None,
    ) -> int:
        if not name.strip() or not reason.strip() or not conditions:
            raise ValueError("Name, reason, and at least one condition are required")
        with self.database._connection() as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO suppressions (
                    name, enabled, created_at, expires_at, reason,
                    match_conditions_json
                ) VALUES (?, 1, ?, ?, ?, ?)
                """,
                (
                    name.strip(),
                    to_db_timestamp(),
                    expires_at,
                    reason.strip(),
                    json.dumps(conditions, ensure_ascii=False),
                ),
            )
        return int(cursor.lastrowid)

    def set_suppression_enabled(self, suppression_id: int, enabled: bool) -> None:
        with self.database._connection() as connection, connection:
            connection.execute(
                "UPDATE suppressions SET enabled=? WHERE id=?",
                (1 if enabled else 0, int(suppression_id)),
            )

    def delete_suppression(self, suppression_id: int) -> None:
        with self.database._connection() as connection, connection:
            connection.execute(
                "DELETE FROM suppressions WHERE id=?",
                (int(suppression_id),),
            )

    def record_suppression_match(self, suppression_id: int) -> None:
        with self.database._connection() as connection, connection:
            connection.execute(
                """
                UPDATE suppressions SET occurrence_count=occurrence_count+1,
                    last_matched_at=? WHERE id=?
                """,
                (to_db_timestamp(), int(suppression_id)),
            )

    def upsert_alert(
        self,
        rule: DetectionRule,
        evidence: list[NormalizedEvent],
        deduplication_key: str,
    ) -> tuple[int, bool, bool]:
        representative = evidence[-1]
        timestamp = str(representative["timestamp"])
        expected, expected_note = _expected_behavior(evidence)
        severity = _effective_severity(rule, representative, expected)
        local_address = _address(representative.get("local_ip"), representative.get("local_port"))
        remote_address = _address(representative.get("remote_ip"), representative.get("remote_port"))
        attacks = rule.get("mitre_attack", [])
        tactics = sorted(
            {
                f"{item.get('tactic_id', '')} {item.get('tactic_name', '')}".strip()
                for item in attacks
                if item.get("tactic_id") or item.get("tactic_name")
            }
        )
        techniques = sorted(
            {
                f"{item.get('technique_id', '')} {item.get('technique_name', '')}".strip()
                for item in attacks
                if item.get("technique_id") or item.get("technique_name")
            }
        )
        summary = " → ".join(
            f"{item['timestamp']} {item['event_type']} ({item.get('process_name', 'Bilinmiyor')})"
            for item in evidence
        )
        now = to_db_timestamp()
        created = False
        occurrence_updated = False
        with self.database._connection() as connection, connection:
            row = connection.execute(
                "SELECT id, status FROM alerts WHERE deduplication_key=?",
                (deduplication_key,),
            ).fetchone()
            if row is None:
                cursor = connection.execute(
                    """
                    INSERT INTO alerts (
                        created_at, updated_at, first_seen, last_seen,
                        occurrence_count, rule_id, rule_version, title,
                        description, severity, category, status, hostname,
                        username, process_name, pid, process_create_time,
                        parent_process_name, executable_path, masked_command_line,
                        local_address, remote_address, remote_ip, mitre_tactics,
                        mitre_techniques, deduplication_key, evidence_summary,
                        evidence_json, expected_behavior, expected_note
                    ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        now,
                        timestamp,
                        timestamp,
                        rule["id"],
                        rule.get("version", "1.0"),
                        rule["title"],
                        rule["description"],
                        severity,
                        rule["category"],
                        representative["hostname"],
                        representative["username"],
                        representative["process_name"],
                        representative["pid"],
                        representative.get("process_create_time"),
                        representative["parent_process_name"],
                        representative["executable_path"],
                        representative["masked_command_line"],
                        local_address,
                        remote_address,
                        representative.get("remote_ip", "—"),
                        json.dumps(tactics, ensure_ascii=False),
                        json.dumps(techniques, ensure_ascii=False),
                        deduplication_key,
                        summary,
                        json.dumps(evidence, ensure_ascii=False, default=str),
                        1 if expected else 0,
                        expected_note,
                    ),
                )
                alert_id = int(cursor.lastrowid)
                created = True
                connection.execute(
                    """
                    INSERT INTO alert_status_history (
                        alert_id, changed_at, old_status, new_status,
                        description, user_note
                    ) VALUES (?, ?, '', 'new', 'Alert created', '')
                    """,
                    (alert_id, now),
                )
            else:
                alert_id = int(row["id"])

            added = 0
            for event in evidence:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO alert_evidence (
                        alert_id, source_type, source_table, source_record_id,
                        timestamp, event_type, process_identity, summary,
                        evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        event["event_type"],
                        event["source_table"],
                        event["source_record_id"],
                        event["timestamp"],
                        event["event_type"],
                        f"{event.get('pid', '—')}|{event.get('process_create_time')}",
                        _evidence_summary(event),
                        json.dumps(event, ensure_ascii=False, default=str),
                    ),
                )
                added += max(cursor.rowcount, 0)
            if not created and added:
                reopen = bool(
                    (rule.get("deduplication") or {}).get("reopen_closed", False)
                )
                should_reopen = reopen and str(row["status"]) == "closed"
                update_sql = (
                    """
                    UPDATE alerts SET updated_at=?, last_seen=?,
                        occurrence_count=occurrence_count+1,
                        evidence_summary=?, evidence_json=?, status='new'
                    WHERE id=?
                    """
                    if should_reopen
                    else """
                    UPDATE alerts SET updated_at=?, last_seen=?,
                        occurrence_count=occurrence_count+1,
                        evidence_summary=?, evidence_json=?
                    WHERE id=?
                    """
                )
                connection.execute(
                    update_sql,
                    (
                        now,
                        timestamp,
                        summary,
                        json.dumps(evidence, ensure_ascii=False, default=str),
                        alert_id,
                    ),
                )
                if should_reopen:
                    connection.execute(
                        """
                        INSERT INTO alert_status_history (
                            alert_id, changed_at, old_status, new_status,
                            description, user_note
                        ) VALUES (?, ?, 'closed', 'new',
                                  'Reopened by rule configuration after new evidence', '')
                        """,
                        (alert_id, now),
                    )
                occurrence_updated = True
            if created or occurrence_updated:
                connection.execute(
                    """
                    UPDATE detection_rules SET match_count=match_count+1,
                        last_match_at=?, updated_at=? WHERE rule_id=?
                    """,
                    (timestamp, now, rule["id"]),
                )
        return alert_id, created, occurrence_updated

    def list_alerts(self, limit: int = DETECTION_UI_LIMIT) -> list[dict[str, Any]]:
        with self.database._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def alert_details(self, alert_id: int) -> dict[str, Any]:
        with self.database._connection() as connection:
            alert = connection.execute(
                "SELECT * FROM alerts WHERE id=?",
                (int(alert_id),),
            ).fetchone()
            if alert is None:
                raise ValueError("Alert not found")
            evidence = connection.execute(
                "SELECT * FROM alert_evidence WHERE alert_id=? ORDER BY timestamp, id",
                (int(alert_id),),
            ).fetchall()
            notes = connection.execute(
                "SELECT * FROM alert_notes WHERE alert_id=? ORDER BY created_at",
                (int(alert_id),),
            ).fetchall()
            history = connection.execute(
                "SELECT * FROM alert_status_history WHERE alert_id=? ORDER BY changed_at",
                (int(alert_id),),
            ).fetchall()
            rule = connection.execute(
                "SELECT content_json FROM detection_rules WHERE rule_id=?",
                (alert["rule_id"],),
            ).fetchone()
        result = dict(alert)
        result["evidence"] = [dict(row) for row in evidence]
        result["notes"] = [dict(row) for row in notes]
        result["status_history"] = [dict(row) for row in history]
        result["rule"] = json.loads(rule[0]) if rule else {}
        result["related_alerts"] = self.similar_alerts(int(alert_id))
        return result

    def set_alert_status(
        self,
        alert_id: int,
        new_status: str,
        user_note: str = "",
    ) -> None:
        new_status = canonical_enum("alert_status", new_status)
        if new_status not in ALERT_STATUSES:
            raise ValueError("Invalid alert status")
        with self.database._connection() as connection, connection:
            row = connection.execute(
                "SELECT status FROM alerts WHERE id=?",
                (int(alert_id),),
            ).fetchone()
            if row is None:
                raise ValueError("Alert not found")
            old_status = str(row["status"])
            if old_status == new_status:
                return
            now = to_db_timestamp()
            connection.execute(
                "UPDATE alerts SET status=?, updated_at=? WHERE id=?",
                (new_status, now, int(alert_id)),
            )
            connection.execute(
                """
                INSERT INTO alert_status_history (
                    alert_id, changed_at, old_status, new_status,
                    description, user_note
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(alert_id),
                    now,
                    old_status,
                    new_status,
                    "User status change",
                    user_note.strip(),
                ),
            )

    def add_alert_note(self, alert_id: int, note_text: str) -> None:
        if not note_text.strip():
            raise ValueError("Note cannot be empty")
        with self.database._connection() as connection, connection:
            connection.execute(
                """
                INSERT INTO alert_notes (alert_id, created_at, author, note_text)
                VALUES (?, ?, ?, ?)
                """,
                (int(alert_id), to_db_timestamp(), getpass.getuser(), note_text.strip()),
            )

    def similar_alerts(self, alert_id: int, limit: int = 20) -> list[dict[str, Any]]:
        with self.database._connection() as connection:
            source = connection.execute(
                "SELECT * FROM alerts WHERE id=?",
                (int(alert_id),),
            ).fetchone()
            if source is None:
                return []
            rows = connection.execute(
                """
                SELECT id, rule_id, title, severity, status, process_name,
                       pid, process_create_time, executable_path,
                       remote_address, last_seen
                FROM alerts
                WHERE id<>?
                ORDER BY last_seen DESC LIMIT 200
                """,
                (int(alert_id),),
            ).fetchall()
        result: list[dict[str, Any]] = []
        source_time = _parse_timestamp(str(source["last_seen"]))
        source_family = str(source["rule_id"]).split("-", 1)[0]
        for row in rows:
            item = dict(row)
            reasons: list[str] = []
            if (
                item["pid"] == source["pid"]
                and (item["process_create_time"] or -1)
                == (source["process_create_time"] or -1)
            ):
                reasons.append("Aynı PID + oluşturulma zamanı")
            if (
                item["executable_path"] not in {"", "—", "Bilinmiyor"}
                and item["executable_path"] == source["executable_path"]
            ):
                reasons.append("Aynı çalıştırılabilir dosya")
            if (
                item["remote_address"] not in {"", "—"}
                and item["remote_address"] == source["remote_address"]
            ):
                reasons.append("Aynı uzak hedef")
            if str(item["rule_id"]).split("-", 1)[0] == source_family:
                reasons.append("Aynı kural ailesi")
            if abs((_parse_timestamp(str(item["last_seen"])) - source_time).total_seconds()) <= 300:
                reasons.append("Aynı 5 dakikalık zaman aralığı")
            if reasons:
                item["similarity_reasons"] = reasons
                result.append(item)
            if len(result) >= limit:
                break
        return result

    def dashboard(self, limit: int = DETECTION_UI_LIMIT) -> dict[str, Any]:
        alerts = self.list_alerts(limit)
        rules = self.list_rules()
        cases = self.list_cases(limit)
        suppressions = self.list_suppressions()
        events = self.list_events(limit=limit)
        since = to_db_timestamp(datetime.now(timezone.utc) - timedelta(hours=24))
        with self.database._connection() as connection:
            attack_rows = connection.execute(
                """
                SELECT mitre_tactics, mitre_techniques,
                       COUNT(*) AS total_count,
                       SUM(CASE WHEN last_seen>=? THEN 1 ELSE 0 END) AS count_24h
                FROM alerts
                WHERE mitre_tactics<>'[]' OR mitre_techniques<>'[]'
                GROUP BY mitre_tactics, mitre_techniques
                ORDER BY total_count DESC
                """,
                (since,),
            ).fetchall()
        return {
            "alerts": alerts,
            "rules": rules,
            "cases": cases,
            "suppressions": suppressions,
            "events": events,
            "attack_coverage": [dict(row) for row in attack_rows],
        }

    def list_suppressions(self) -> list[dict[str, Any]]:
        with self.database._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM suppressions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def create_case(
        self,
        title: str,
        description: str,
        severity: str,
        alert_ids: list[int],
    ) -> int:
        severity = canonical_enum("severity", severity)
        if not title.strip():
            raise ValueError("Case title cannot be empty")
        if severity not in SEVERITIES:
            raise ValueError("Invalid case severity")
        now = to_db_timestamp()
        case_key = f"CASE-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
        with self.database._connection() as connection, connection:
            alerts = []
            if alert_ids:
                placeholders = ",".join("?" for _ in alert_ids)
                alerts = connection.execute(
                    # Placeholder text is generated only from '?' characters.
                    f"SELECT * FROM alerts WHERE id IN ({placeholders})",  # nosec
                    [int(item) for item in alert_ids],
                ).fetchall()
            first = min((str(row["first_seen"]) for row in alerts), default=now)
            last = max((str(row["last_seen"]) for row in alerts), default=now)
            hostname = str(alerts[0]["hostname"]) if alerts else "Bilinmiyor"
            cursor = connection.execute(
                """
                INSERT INTO cases (
                    case_id, title, description, severity, status, created_at,
                    updated_at, first_event_at, last_event_at, hostname, summary
                ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_key,
                    title.strip(),
                    description.strip(),
                    severity,
                    now,
                    now,
                    first,
                    last,
                    hostname,
                    f"Created with {len(alerts)} alerts",
                ),
            )
            case_pk = int(cursor.lastrowid)
            for alert_id in alert_ids:
                connection.execute(
                    "DELETE FROM case_alerts WHERE alert_id=?",
                    (int(alert_id),),
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO case_alerts(case_id, alert_id, added_at)
                    VALUES (?, ?, ?)
                    """,
                    (case_pk, int(alert_id), now),
                )
                connection.execute(
                    "UPDATE alerts SET case_id=? WHERE id=?",
                    (case_pk, int(alert_id)),
                )
        return case_pk

    def add_alert_to_case(self, case_id: int, alert_id: int) -> None:
        now = to_db_timestamp()
        with self.database._connection() as connection, connection:
            connection.execute(
                "DELETE FROM case_alerts WHERE alert_id=?",
                (int(alert_id),),
            )
            connection.execute(
                "INSERT OR IGNORE INTO case_alerts(case_id, alert_id, added_at) VALUES (?, ?, ?)",
                (int(case_id), int(alert_id), now),
            )
            connection.execute(
                "UPDATE alerts SET case_id=?, updated_at=? WHERE id=?",
                (int(case_id), now, int(alert_id)),
            )
            self._refresh_case_times(connection, int(case_id), now)

    def remove_alert_from_case(self, case_id: int, alert_id: int) -> None:
        now = to_db_timestamp()
        with self.database._connection() as connection, connection:
            connection.execute(
                "DELETE FROM case_alerts WHERE case_id=? AND alert_id=?",
                (int(case_id), int(alert_id)),
            )
            connection.execute(
                "UPDATE alerts SET case_id=NULL, updated_at=? WHERE id=? AND case_id=?",
                (now, int(alert_id), int(case_id)),
            )
            self._refresh_case_times(connection, int(case_id), now)

    def list_cases(self, limit: int = DETECTION_UI_LIMIT) -> list[dict[str, Any]]:
        with self.database._connection() as connection:
            rows = connection.execute(
                """
                SELECT c.*, COUNT(ca.alert_id) AS alert_count
                FROM cases c LEFT JOIN case_alerts ca ON ca.case_id=c.id
                GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def case_details(self, case_id: int) -> dict[str, Any]:
        with self.database._connection() as connection:
            case = connection.execute(
                "SELECT * FROM cases WHERE id=?",
                (int(case_id),),
            ).fetchone()
            if case is None:
                raise ValueError("Case not found")
            alerts = connection.execute(
                """
                SELECT a.* FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id
                WHERE ca.case_id=? ORDER BY a.first_seen
                """,
                (int(case_id),),
            ).fetchall()
            timeline = connection.execute(
                """
                SELECT e.* FROM alert_evidence e
                JOIN case_alerts ca ON ca.alert_id=e.alert_id
                WHERE ca.case_id=? ORDER BY e.timestamp, e.id
                """,
                (int(case_id),),
            ).fetchall()
            notes = connection.execute(
                "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at",
                (int(case_id),),
            ).fetchall()
        result = dict(case)
        result["alerts"] = [dict(row) for row in alerts]
        result["timeline"] = [dict(row) for row in timeline]
        result["notes"] = [dict(row) for row in notes]
        return result

    def update_case(
        self,
        case_id: int,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        conclusion: str | None = None,
    ) -> None:
        if severity is not None:
            severity = canonical_enum("severity", severity)
        if status is not None:
            status = canonical_enum("case_status", status)
        if severity is not None and severity not in SEVERITIES:
            raise ValueError("Invalid case severity")
        if status is not None and status not in CASE_STATUSES:
            raise ValueError("Invalid case status")
        fields: list[str] = []
        values: list[Any] = []
        for field, value in (
            ("title", title),
            ("description", description),
            ("severity", severity),
            ("status", status),
            ("conclusion", conclusion),
        ):
            if value is not None:
                fields.append(f"{field}=?")
                values.append(value)
        if not fields:
            return
        fields.append("updated_at=?")
        values.extend((to_db_timestamp(), int(case_id)))
        with self.database._connection() as connection, connection:
            connection.execute(
                # Field names come from the fixed tuple directly above.
                f"UPDATE cases SET {', '.join(fields)} WHERE id=?",  # nosec
                values,
            )

    def add_case_note(self, case_id: int, note_text: str) -> None:
        if not note_text.strip():
            raise ValueError("Note cannot be empty")
        with self.database._connection() as connection, connection:
            connection.execute(
                "INSERT INTO case_notes(case_id, created_at, author, note_text) VALUES (?, ?, ?, ?)",
                (int(case_id), to_db_timestamp(), getpass.getuser(), note_text.strip()),
            )

    @staticmethod
    def _refresh_case_times(connection: Any, case_id: int, now: str) -> None:
        row = connection.execute(
            """
            SELECT MIN(a.first_seen), MAX(a.last_seen), COUNT(*)
            FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id
            WHERE ca.case_id=?
            """,
            (case_id,),
        ).fetchone()
        connection.execute(
            """
            UPDATE cases SET first_event_at=COALESCE(?, first_event_at),
                last_event_at=COALESCE(?, last_event_at),
                summary=?, updated_at=? WHERE id=?
            """,
            (row[0], row[1], f"{row[2]} linked alerts", now, case_id),
        )

    @staticmethod
    def deduplication_key(
        rule: DetectionRule,
        event: NormalizedEvent,
    ) -> str:
        config = rule.get("deduplication") or {}
        fields = config.get("fields") or rule.get("group_by") or ["event_id"]
        parts = [rule["id"]]
        for field in fields:
            parts.append(f"{field}={_nested(event, str(field))}")
        bucket = config.get("bucket_seconds")
        if isinstance(bucket, int) and bucket > 0:
            try:
                stamp = datetime.fromisoformat(
                    str(event["timestamp"]).replace("Z", "+00:00")
                ).timestamp()
                parts.append(f"bucket={int(stamp // bucket)}")
            except ValueError:
                pass
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _event_from_row(row: dict[str, Any]) -> NormalizedEvent:
        try:
            additional = json.loads(row.pop("additional_data_json"))
        except (json.JSONDecodeError, KeyError):
            additional = {}
        row["additional_data"] = additional
        row["source_record_id"] = int(row["source_record_id"])
        return row  # type: ignore[return-value]


def _nested(event: dict[str, Any], field: str) -> Any:
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return current


def _address(ip: Any, port: Any) -> str:
    if ip in {None, "", "—"}:
        return "—"
    return f"{ip}:{port}" if port not in {None, "", "—"} else str(ip)


def _expected_behavior(events: list[NormalizedEvent]) -> tuple[bool, str]:
    for event in events:
        additional = event.get("additional_data", {})
        if additional.get("is_expected"):
            return True, str(additional.get("expected_note", ""))
    return False, ""


def _effective_severity(
    rule: DetectionRule,
    event: NormalizedEvent,
    expected: bool,
) -> str:
    severity = str(rule["severity"])
    if rule["id"] == "NET-103":
        severity = {
            "loopback": "info",
            "private": "low",
            "all_interfaces": "medium",
        }.get(str(event.get("address_scope")), severity)
    if expected:
        order = ["info", "low", "medium", "high", "critical"]
        severity = order[max(0, order.index(severity) - 1)]
    return severity


def _evidence_summary(event: NormalizedEvent) -> str:
    address = (
        _address(event.get("remote_ip"), event.get("remote_port"))
        if event.get("remote_ip") not in {None, "", "—"}
        else _address(event.get("local_ip"), event.get("local_port"))
    )
    return (
        f"{event.get('process_name', 'Bilinmiyor')} "
        f"{event.get('event_type', 'olay')} {address}"
    ).strip()


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
