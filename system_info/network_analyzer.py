"""Connect one network snapshot to baselines, events, and findings."""

from __future__ import annotations

from .listener_tracker import ListenerTracker
from .connection_history import ConnectionEventTracker
from .network_models import NetworkSnapshot
from .network_repository import NetworkRepository


class NetworkAnalyzer:
    def __init__(self, repository: NetworkRepository) -> None:
        self.repository = repository
        self.listener_tracker = ListenerTracker()
        self.connection_tracker = ConnectionEventTracker()
        self._initialized = False

    def process(self, snapshot: NetworkSnapshot) -> dict:
        events = self.listener_tracker.update(
            snapshot.listeners, snapshot.captured_at
        )
        connection_events = self.connection_tracker.update(
            [dict(item) for item in snapshot.connections], snapshot.captured_at
        )
        result = self.repository.process_snapshot(
            snapshot,
            events,
            connection_events=[] if not self._initialized else connection_events,
            baseline_only=not self._initialized,
        )
        self._initialized = True
        dashboard = self.repository.query_dashboard()
        return {
            **dashboard,
            "generated_event_count": result["events"],
            "generated_finding_count": result["findings"],
        }
