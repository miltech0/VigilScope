from contextlib import nullcontext
from types import SimpleNamespace

import psutil

from system_info.process_collector import ProcessCollector
from system_info.process_models import (
    ACCESS_DENIED,
    ENDED,
    normalize_process_data,
)


class FakeProcess:
    pid = 42

    def __init__(self) -> None:
        self.cpu_calls = 0

    def oneshot(self):
        return nullcontext()

    def create_time(self):
        return 1_700_000_000.0

    def name(self):
        return "python.exe"

    def ppid(self):
        return 1

    def username(self):
        return "Alice"

    def status(self):
        return "running"

    def exe(self):
        return r"C:\Python\python.exe"

    def cwd(self):
        return r"C:\Work"

    def cmdline(self):
        return ["python.exe", "app.py", "--password", "secret"]

    def memory_info(self):
        return SimpleNamespace(rss=100 * 1024 * 1024)

    def memory_percent(self):
        return 2.5

    def num_threads(self):
        return 8

    def cpu_percent(self, interval=None):
        assert interval is None
        self.cpu_calls += 1
        return 33.0

    def open_files(self):
        return []

    def children(self, recursive=False):
        assert recursive is False
        return []

    def parent(self):
        return None


class DeniedProcess(FakeProcess):
    def _denied(self, *args, **kwargs):
        raise psutil.AccessDenied(self.pid)

    name = ppid = username = status = exe = cwd = cmdline = _denied


class EndedProcess(FakeProcess):
    def _ended(self, *args, **kwargs):
        raise psutil.NoSuchProcess(self.pid)

    create_time = name = ppid = username = status = exe = cwd = cmdline = _ended


def test_process_data_is_normalized() -> None:
    record = normalize_process_data(
        {
            "pid": "12",
            "ppid": "1",
            "name": "app.exe",
            "status": "sleeping",
            "ram_bytes": 10 * 1024 * 1024,
            "cpu_percent": "5.5",
        },
        network_count=3,
    )
    assert record["pid"] == 12
    assert record["status"] == "sleeping"
    assert record["ram_mb"] == 10.0
    assert record["network_count"] == 3


def test_first_cpu_sample_is_zero_then_non_blocking_value_is_used() -> None:
    process = FakeProcess()
    collector = ProcessCollector(process_iter=lambda: [process])

    first = collector.collect_processes({42: 2})[0]
    second = collector.collect_processes({42: 2})[0]

    assert first["cpu_percent"] == 0.0
    assert second["cpu_percent"] == 33.0
    assert second["network_count"] == 2
    assert second["command_line"] == "python.exe app.py --password ***"


def test_access_denied_is_safe() -> None:
    record = ProcessCollector(
        process_iter=lambda: [DeniedProcess()]
    ).collect_processes()[0]
    assert record["name"] == ACCESS_DENIED
    assert record["username"] == ACCESS_DENIED
    assert record["exe"] == ACCESS_DENIED


def test_no_such_process_is_safe() -> None:
    record = ProcessCollector(
        process_iter=lambda: [EndedProcess()]
    ).collect_processes()[0]
    assert record["name"] == ENDED
    assert record["status"] == ENDED


def test_process_details_keep_the_stable_cpu_sample() -> None:
    process = FakeProcess()
    base = ProcessCollector(process_iter=lambda: [process]).collect_processes()[0]
    base["cpu_percent"] = 21.5
    details = ProcessCollector(
        process_factory=lambda pid: process
    ).collect_details(base, [])
    assert details["cpu_percent"] == 21.5
