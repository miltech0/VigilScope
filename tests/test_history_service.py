from system_info.database import HistoryDatabase
from system_info.history_service import HistoryService


def test_history_service_prevents_duplicate_recording_loops(tmp_path) -> None:
    database = HistoryDatabase(tmp_path / "service.db")
    database.initialize()
    service = HistoryService(
        database,
        measurement_interval=60,
        maintenance_interval=60,
    )

    try:
        assert service.start() is True
        assert service.start() is False
    finally:
        assert service.stop() is True
