from system_info.process_filters import filter_processes, sort_processes


def record(
    name: str,
    pid: int,
    username: str,
    cpu: float,
    ram: float,
    status: str = "Çalışıyor",
) -> dict[str, object]:
    return {
        "name": name,
        "pid": pid,
        "username": username,
        "exe": rf"C:\Apps\{name}",
        "status": status,
        "network_count": 1 if pid == 20 else 0,
        "cpu_percent": cpu,
        "ram_mb": ram,
        "ppid": 1,
        "parent_name": "parent.exe",
        "ram_percent": 1.0,
        "num_threads": 2,
        "create_time": 1.0,
    }


RECORDS = [
    record("python.exe", 20, "Alice", 12.5, 500),
    record("chrome.exe", 5, "Bob", 2.0, 900, "Uyuyor"),
    record("worker.exe", 100, "Alice", 45.0, 100),
]


def test_name_pid_and_path_search_is_case_insensitive() -> None:
    assert filter_processes(RECORDS, query="PYTHON").records == [RECORDS[0]]
    assert filter_processes(RECORDS, query="100").records == [RECORDS[2]]
    assert filter_processes(RECORDS, query=r"apps\chrome").records == [RECORDS[1]]


def test_user_status_network_cpu_and_ram_filters() -> None:
    assert len(filter_processes(RECORDS, query="alice").records) == 2
    assert filter_processes(RECORDS, status="Uyuyor").records == [RECORDS[1]]
    assert filter_processes(RECORDS, network_only=True).records == [RECORDS[0]]
    assert filter_processes(RECORDS, minimum_cpu="10").records == [
        RECORDS[0],
        RECORDS[2],
    ]
    assert filter_processes(RECORDS, minimum_ram_mb="600").records == [RECORDS[1]]


def test_invalid_numeric_filters_are_ignored() -> None:
    result = filter_processes(RECORDS, minimum_cpu="abc", minimum_ram_mb="-2")
    assert result.records == RECORDS
    assert result.invalid_fields == ("CPU", "RAM")


def test_numeric_and_text_sorting() -> None:
    assert [item["pid"] for item in sort_processes(RECORDS, "pid")] == [5, 20, 100]
    assert [item["name"] for item in sort_processes(RECORDS, "name")] == [
        "chrome.exe",
        "python.exe",
        "worker.exe",
    ]
    assert [item["cpu_percent"] for item in sort_processes(
        RECORDS, "cpu_percent", descending=True
    )] == [45.0, 12.5, 2.0]

