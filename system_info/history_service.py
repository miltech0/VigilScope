"""Run measurement writes, event writes, and maintenance in one worker."""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Mapping
from typing import Any

import psutil

from .config import (
    MAINTENANCE_INTERVAL_SECONDS,
    MEASUREMENT_INTERVAL_SECONDS,
)
from .database import DatabaseError, HistoryDatabase, to_db_timestamp
from .metrics import collect_disks


class HistoryService:
    def __init__(
        self,
        database: HistoryDatabase,
        measurement_interval: float = MEASUREMENT_INTERVAL_SECONDS,
        maintenance_interval: float = MAINTENANCE_INTERVAL_SECONDS,
    ) -> None:
        self.database = database
        self.measurement_interval = measurement_interval
        self.maintenance_interval = maintenance_interval
        self.notifications: queue.Queue[tuple[str, str]] = queue.Queue()
        self._commands: queue.Queue[
            tuple[str, list[Mapping[str, Any]]] | tuple[str, None]
        ] = queue.Queue()
        self._stop_event = threading.Event()
        self._start_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._active_connection_count = 0

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Tek bir kayıt döngüsü başlatır; zaten çalışıyorsa False döndürür."""
        with self._start_lock:
            if self.is_running:
                return False
            self._stop_event.clear()
            while True:
                try:
                    self._commands.get_nowait()
                except queue.Empty:
                    break
            self._thread = threading.Thread(
                target=self._run,
                name="system-history-recorder",
                daemon=True,
            )
            self._thread.start()
            return True

    def stop(self, timeout: float = 3.0) -> bool:
        thread = self._thread
        if thread is None or not thread.is_alive():
            self._stop_event.set()
            return True

        # FIFO ordering writes pending events before the stop command.
        self._commands.put(("stop", None))
        thread.join(timeout=timeout)
        if thread.is_alive():
            self._stop_event.set()
            self._commands.put(("stop", None))
            thread.join(timeout=0.2)
        else:
            self._stop_event.set()
        return not thread.is_alive()

    def set_active_connection_count(self, count: int) -> None:
        with self._state_lock:
            self._active_connection_count = max(0, int(count))

    def record_connection_events(self, events: list[Mapping[str, Any]]) -> None:
        if events and not self._stop_event.is_set():
            self._commands.put(("events", list(events)))

    def record_process_events(self, events: list[Mapping[str, Any]]) -> None:
        if events and not self._stop_event.is_set():
            self._commands.put(("process_events", list(events)))

    def _run(self) -> None:
        next_measurement = time.monotonic()
        next_maintenance = time.monotonic()

        while not self._stop_event.is_set():
            now = time.monotonic()
            timeout = max(0.0, min(next_measurement, next_maintenance) - now)
            try:
                command, payload = self._commands.get(timeout=timeout)
            except queue.Empty:
                command, payload = "", None

            if command == "stop":
                break
            if command == "events" and payload:
                self._safe_insert_events(payload)
            if command == "process_events" and payload:
                self._safe_insert_process_events(payload)

            now = time.monotonic()
            if now >= next_measurement and not self._stop_event.is_set():
                self._safe_record_measurement()
                next_measurement = now + self.measurement_interval
            if now >= next_maintenance and not self._stop_event.is_set():
                self._safe_cleanup()
                next_maintenance = now + self.maintenance_interval

    def _collect_measurement(self) -> dict[str, str | int | float]:
        memory = psutil.virtual_memory()
        disks = collect_disks()
        disk_percent = float(disks[0]["percent"]) if disks else 0.0
        network = psutil.net_io_counters()
        net_bytes_sent = int(getattr(network, "bytes_sent", 0) or 0)
        net_bytes_recv = int(getattr(network, "bytes_recv", 0) or 0)
        with self._state_lock:
            connection_count = self._active_connection_count

        return {
            "timestamp": to_db_timestamp(),
            "cpu_percent": float(psutil.cpu_percent(interval=None)),
            "ram_percent": float(memory.percent),
            "ram_used_bytes": int(memory.used),
            "disk_percent": disk_percent,
            "active_connections": connection_count,
            "net_bytes_sent": net_bytes_sent,
            "net_bytes_recv": net_bytes_recv,
        }

    def _safe_record_measurement(self) -> None:
        try:
            self.database.insert_measurement(self._collect_measurement())
        except (DatabaseError, OSError, RuntimeError, TypeError, ValueError) as exc:
            self.notifications.put(("error", f"Ölçüm kaydedilemedi: {exc}"))

    def _safe_insert_events(self, events: list[Mapping[str, Any]]) -> None:
        try:
            self.database.insert_connection_events(events)
        except (DatabaseError, KeyError, TypeError, ValueError) as exc:
            self.notifications.put(("error", f"Bağlantı olayları kaydedilemedi: {exc}"))

    def _safe_insert_process_events(
        self, events: list[Mapping[str, Any]]
    ) -> None:
        try:
            self.database.insert_process_events(events)
        except (DatabaseError, KeyError, TypeError, ValueError) as exc:
            self.notifications.put(("error", f"İşlem olayları kaydedilemedi: {exc}"))

    def _safe_cleanup(self) -> None:
        try:
            self.database.cleanup_old_records()
        except DatabaseError as exc:
            self.notifications.put(("error", f"Geçmiş temizlenemedi: {exc}"))
