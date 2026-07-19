"""Non-blocking, error-isolated process collection with psutil."""

from __future__ import annotations

import logging
import time
from contextlib import nullcontext
from typing import Any, Callable, Iterable

import psutil

from .process_models import (
    ACCESS_DENIED,
    ENDED,
    UNKNOWN,
    ProcessIdentity,
    ProcessRecord,
    format_uptime,
    normalize_process_data,
    process_identity,
)
from .process_security import mask_sensitive_command_line

LOGGER = logging.getLogger(__name__)


class ProcessCollector:
    def __init__(
        self,
        process_iter: Callable[[], Iterable[Any]] | None = None,
        process_factory: Callable[[int], Any] | None = None,
    ) -> None:
        self._process_iter = process_iter or psutil.process_iter
        self._process_factory = process_factory or psutil.Process
        self._cpu_primed: set[ProcessIdentity] = set()

    def collect_processes(
        self, network_counts: dict[int, int] | None = None
    ) -> list[ProcessRecord]:
        counts = network_counts or {}
        records: list[ProcessRecord] = []
        try:
            processes = list(self._process_iter())
        except (psutil.Error, OSError):
            return records

        for process in processes:
            try:
                record = self._collect_one(process, counts)
            except Exception:
                # One unexpected process object must not abort the full scan.
                LOGGER.debug("Unexpected process collection failure", exc_info=True)
            else:
                records.append(record)

        names = {int(record["pid"]): record["name"] for record in records}
        for record in records:
            ppid = int(record.get("ppid", 0))
            record["parent_name"] = names.get(ppid, UNKNOWN) if ppid else UNKNOWN
        active_identities = {process_identity(record) for record in records}
        self._cpu_primed.intersection_update(active_identities)
        return records

    def _collect_one(
        self, process: Any, network_counts: dict[int, int]
    ) -> ProcessRecord:
        pid = int(getattr(process, "pid", 0))
        context = process.oneshot() if hasattr(process, "oneshot") else nullcontext()
        raw: dict[str, Any] = {"pid": pid}
        try:
            with context:
                raw["create_time"] = self._safe(process.create_time)
                raw["name"] = self._safe(process.name)
                raw["ppid"] = self._safe(process.ppid, 0)
                raw["username"] = self._safe(process.username)
                raw["status"] = self._safe(process.status)
                raw["exe"] = self._safe(process.exe)
                raw["cwd"] = self._safe(process.cwd)
                command = self._safe(process.cmdline)
                raw["command_line"] = mask_sensitive_command_line(command)
                memory = self._safe(process.memory_info, None)
                raw["ram_bytes"] = getattr(memory, "rss", 0)
                raw["ram_percent"] = self._safe(process.memory_percent, 0.0)
                raw["num_threads"] = self._safe(process.num_threads, 0)

                temporary = normalize_process_data(raw, network_counts.get(pid, 0))
                identity = process_identity(temporary)
                cpu = self._safe(lambda: process.cpu_percent(interval=None), 0.0)
                if identity not in self._cpu_primed:
                    raw["cpu_percent"] = 0.0
                    self._cpu_primed.add(identity)
                else:
                    raw["cpu_percent"] = cpu
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            raw["_ended"] = True
            raw.setdefault("name", ENDED)
        except (psutil.AccessDenied, PermissionError):
            raw.setdefault("name", ACCESS_DENIED)
            raw.setdefault("status", ACCESS_DENIED)
        return normalize_process_data(raw, network_counts.get(pid, 0))

    def collect_details(
        self,
        base_record: ProcessRecord,
        connections: list[dict[str, str | int]],
    ) -> ProcessRecord:
        pid = int(base_record["pid"])
        details = dict(base_record)
        try:
            process = self._process_factory(pid)
            expected = base_record.get("create_time")
            actual = self._safe(process.create_time)
            if (
                isinstance(expected, (int, float))
                and isinstance(actual, (int, float))
                and abs(float(expected) - float(actual)) > 0.000_001
            ):
                raise psutil.NoSuchProcess(pid)

            updated = self._collect_one(
                process,
                {pid: sum(1 for item in connections if item.get("pid") == pid)},
            )
            # A new psutil.Process instance naturally reports zero on its first
            # CPU call; retain the stable value from the main scan in details.
            updated["cpu_percent"] = base_record.get(
                "cpu_percent", updated["cpu_percent"]
            )
            updated["parent_name"] = base_record.get("parent_name", UNKNOWN)
            details.update(updated)
            details["uptime"] = format_uptime(
                details.get("create_time"), time.time()
            )
            open_files = self._safe(process.open_files, None)
            details["open_files_count"] = (
                len(open_files) if isinstance(open_files, list) else open_files or UNKNOWN
            )
            details["children"] = self._child_labels(process)
            details["parent_chain"] = self._parent_chain(process)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            details["status"] = ENDED
            details["uptime"] = UNKNOWN
            details["open_files_count"] = UNKNOWN
            details["children"] = []
            details["parent_chain"] = []
        except (psutil.AccessDenied, PermissionError):
            details["open_files_count"] = ACCESS_DENIED
            details["children"] = [ACCESS_DENIED]
            details["parent_chain"] = [ACCESS_DENIED]

        details["connections"] = [
            item for item in connections if item.get("pid") == pid
        ]
        return details

    def _child_labels(self, process: Any) -> list[str]:
        children = self._safe(lambda: process.children(recursive=False), [])
        if not isinstance(children, list):
            return [str(children)]
        labels = []
        for child in children:
            name = self._safe(child.name)
            labels.append(f"{name} (PID {getattr(child, 'pid', '?')})")
        return labels

    def _parent_chain(self, process: Any) -> list[str]:
        chain: list[str] = []
        seen: set[int] = set()
        current = process
        for _ in range(64):
            parent = self._safe(current.parent, None)
            if parent is None:
                break
            if not hasattr(parent, "pid"):
                chain.append(str(parent))
                break
            pid = int(parent.pid)
            if pid in seen:
                chain.append("Döngü algılandı")
                break
            seen.add(pid)
            chain.append(f"{self._safe(parent.name)} (PID {pid})")
            current = parent
        return chain

    @staticmethod
    def _safe(call: Callable[[], Any], default: Any = UNKNOWN) -> Any:
        try:
            return call()
        except (psutil.AccessDenied, PermissionError):
            return ACCESS_DENIED
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return ENDED
        except (OSError, RuntimeError, ValueError):
            return default
