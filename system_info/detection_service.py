"""Incremental normalization, correlation, checkpoint, and alert service."""

from __future__ import annotations

import queue
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from .alert_repository import SOURCE_TABLES, AlertRepository
from .config import (
    DETECTION_BATCH_SIZE,
    DETECTION_NOTIFICATION_MIN_SEVERITY,
    DETECTION_POLL_INTERVAL_SECONDS,
    DETECTION_PREVIEW_LIMIT,
)
from .correlation_engine import correlate, max_correlation_window
from .detection_models import DetectionRule, NormalizedEvent, SEVERITIES
from .event_normalizer import normalize_source_event
from .rule_loader import load_rule_file
from .rule_validator import validate_rule
from .suppression_service import SuppressionService


class DetectionService:
    def __init__(
        self,
        repository: AlertRepository,
        *,
        baseline_existing: bool = True,
    ) -> None:
        self.repository = repository
        self.suppressions = SuppressionService(repository)
        self.repository.sync_builtin_rules(load_rule_file())
        self.repository.initialize_checkpoints(baseline_existing)
        self._run_lock = threading.Lock()

    def process_once(self) -> dict[str, Any]:
        if not self._run_lock.acquire(blocking=False):
            return {"busy": True, "created_alerts": [], "processed_events": 0}
        try:
            rules = self.repository.list_rules(enabled_only=True)
            created_alerts: list[dict[str, Any]] = []
            source_batches: dict[str, list[dict[str, Any]]] = {}
            normalized: list[NormalizedEvent] = []
            for source in SOURCE_TABLES:
                checkpoint = self.repository.checkpoint(source)
                rows = self.repository.fetch_source_rows(
                    source,
                    checkpoint,
                    DETECTION_BATCH_SIZE,
                )
                if not rows:
                    continue
                source_batches[source] = rows
                for row in rows:
                    event = normalize_source_event(source, row)
                    if event is None:
                        continue
                    self.repository.insert_normalized_event(event)
                    normalized.append(event)
            normalized.sort(key=lambda event: str(event.get("timestamp", "")))
            self._evaluate_batch(normalized, rules, created_alerts)
            for source, rows in source_batches.items():
                # Recognized source records that cannot normalize are skipped safely.
                self.repository.advance_checkpoint(source, int(rows[-1]["id"]))
            return {
                "busy": False,
                "created_alerts": created_alerts,
                "processed_events": sum(len(rows) for rows in source_batches.values()),
            }
        finally:
            self._run_lock.release()

    def preview_rule(
        self,
        rule: dict[str, Any],
        since: datetime,
        limit: int = DETECTION_PREVIEW_LIMIT,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        validated = validate_rule(rule)
        events = self.repository.recent_events(since, limit, until)
        matches: list[dict[str, Any]] = []
        keys: set[str] = set()
        for event in events:
            evidence = correlate(validated, events, event)
            if not evidence:
                continue
            key = self.repository.deduplication_key(validated, evidence[-1])
            if key in keys:
                continue
            keys.add(key)
            matches.append(
                {
                    "deduplication_key": key,
                    "timestamp": event["timestamp"],
                    "process_name": event["process_name"],
                    "pid": event["pid"],
                    "event_type": event["event_type"],
                    "evidence_count": len(evidence),
                }
            )
        return {
            "total_matches": len(matches),
            "samples": matches[:100],
            "first_match": matches[0]["timestamp"] if matches else None,
            "last_match": matches[-1]["timestamp"] if matches else None,
            "possible_alerts": len(keys),
            "truncated": len(events) >= limit,
        }

    def _evaluate_batch(
        self,
        new_events: list[NormalizedEvent],
        rules: list[DetectionRule],
        created_alerts: list[dict[str, Any]],
    ) -> None:
        if not new_events or not rules:
            return
        max_window = max(max_correlation_window(rules), 1)
        earliest = min(_parse_time(event["timestamp"]) for event in new_events)
        recent = self.repository.recent_events(
            earliest - timedelta(seconds=max_window),
            DETECTION_PREVIEW_LIMIT,
        )
        new_ids = {event["event_id"] for event in new_events}
        for rule in rules:
            triggers = recent if rule.get("correlation") else new_events
            for event in triggers:
                evidence = correlate(rule, recent, event)
                if not evidence:
                    continue
                if not any(item["event_id"] in new_ids for item in evidence):
                    continue
                suppression_event = dict(event)
                suppression_event["rule_id"] = rule["id"]
                suppression = self.suppressions.matching_suppression(
                    suppression_event  # type: ignore[arg-type]
                )
                if suppression:
                    self.repository.record_suppression_match(int(suppression["id"]))
                    continue
                dedup = self.repository.deduplication_key(rule, evidence[-1])
                alert_id, created, occurrence = self.repository.upsert_alert(
                    rule,
                    evidence,
                    dedup,
                )
                if created:
                    created_alerts.append(
                        {
                            "id": alert_id,
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "notify": _should_notify(rule["severity"]),
                        }
                    )


class DetectionWorker:
    """Tek daemon işçisi; Tkinter'a dokunmadan periyodik artımlı analiz yapar."""

    def __init__(
        self,
        service: DetectionService,
        interval_seconds: float = DETECTION_POLL_INTERVAL_SECONDS,
    ) -> None:
        self.service = service
        self.interval_seconds = max(0.2, float(interval_seconds))
        self.notifications: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="detection-worker",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        self._thread = None

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                result = self.service.process_once()
                if result.get("processed_events") or result.get("created_alerts"):
                    self.notifications.put({"kind": "refresh", **result})
            except Exception as exc:
                self.notifications.put(
                    {
                        "kind": "error",
                        "message": f"Tespit motoru hatası: {exc}",
                    }
                )
            self._stop_event.wait(self.interval_seconds)


def _should_notify(severity: str) -> bool:
    threshold = SEVERITIES.index(DETECTION_NOTIFICATION_MIN_SEVERITY)
    try:
        return SEVERITIES.index(severity) >= threshold
    except ValueError:
        return False


def _parse_time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
