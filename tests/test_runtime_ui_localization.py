from __future__ import annotations

import tkinter as tk

import pytest

from system_info.app import SystemInfoApp
from system_info.settings import SettingsStore


def test_runtime_language_switch_updates_tabs_columns_and_filters(tmp_path) -> None:
    settings = SettingsStore(tmp_path, lambda: "tr-TR")
    try:
        app = SystemInfoApp(tmp_path / "ui.db", settings)
    except tk.TclError as exc:
        pytest.skip(f"Tk is unavailable: {exc}")
    try:
        assert app.notebook.tab(app.overview_tab, "text") == "Genel"
        app._select_language("en")
        assert app.title().startswith("VigilScope")
        assert [app.notebook.tab(item, "text") for item in app.notebook.tabs()] == [
            "Overview",
            "Network Analysis",
            "Detections",
            "Processes",
            "History",
        ]
        assert [
            app.network_tab.views.tab(item, "text")
            for item in app.network_tab.views.tabs()
        ] == [
            "Overview",
            "Listening Ports",
            "Remote Endpoints",
            "Network Events",
            "Findings",
        ]
        assert app.connection_tree.heading("process_name", "text") == "Process Name"
        assert app.protocol_filter_var.get() == "All"
        assert app.processes_tab.table.heading("name", "text").startswith(
            "Process Name"
        )
        app._select_language("tr")
        assert app.notebook.tab(app.overview_tab, "text") == "Genel"
        assert settings.load()["language"] == "tr"
    finally:
        app._close()

