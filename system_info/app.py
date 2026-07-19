"""Tkinter desktop interface for VigilScope."""

from __future__ import annotations

import queue
import socket
import threading
import tkinter as tk
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

import psutil

from .charts import HistoryChart
from .alert_details import AlertDetailWindow
from .alert_repository import AlertRepository
from .case_details import CaseDetailWindow
from .config import (
    HISTORY_RANGES,
    PROCESS_REFRESH_INTERVAL_SECONDS,
    get_app_data_dir,
    get_database_path,
    get_legacy_app_data_dir,
)
from .connection_history import ConnectionEventTracker, filter_connection_events
from .database import DatabaseError, HistoryDatabase, to_db_timestamp
from .detection_exporting import (
    export_detection_csv,
    export_detection_json,
    export_single_alert_json,
    export_single_case_json,
)
from .detection_service import DetectionService, DetectionWorker
from .detection_tab import DetectionTab
from .exporting import export_history_csv, export_history_json
from .history_service import HistoryService
from .metrics import (
    collect_disks,
    cpu_name,
    filter_connections,
    format_bytes,
)
from .dns_cache import DnsResolverCache
from .network_analyzer import NetworkAnalyzer
from .network_details import NetworkDetailWindow
from .network_models import NetworkSnapshot
from .network_repository import NetworkRepository
from .network_snapshot import collect_network_snapshot
from .network_tab import NetworkAnalysisTab
from .process_collector import ProcessCollector
from .process_details import ProcessDetailWindow
from .process_history import ProcessEventTracker, filter_process_events
from .process_models import ProcessRecord, process_identity
from .process_tab import ProcessTab
from .rule_editor import RuleEditorWindow
from .data_migration import LegacyDataMigrationError, migrate_legacy_database
from .i18n import configure_i18n, format_datetime, localize_widget_tree, t
from .product import PRODUCT_NAME, PRODUCT_SLUG
from .settings import SettingsStore
from .assets import load_flag_image

Connection = dict[str, str | int]


class Tooltip:
    """Small keyboard- and mouse-triggered tooltip for compact controls."""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.window: tk.Toplevel | None = None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<FocusIn>", self.show, add="+")
        widget.bind("<FocusOut>", self.hide, add="+")

    def show(self, _event: tk.Event | None = None) -> None:
        if self.window is not None:
            return
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.configure(bg="#475569")
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.window.geometry(f"+{x}+{y}")
        tk.Label(
            self.window,
            text=self.text,
            bg="#1e293b",
            fg="#f8fafc",
            padx=8,
            pady=4,
        ).pack()

    def hide(self, _event: tk.Event | None = None) -> None:
        if self.window is not None:
            self.window.destroy()
            self.window = None


class MetricCard(ttk.Frame):
    """Summary card with a title, value, and progress bar."""

    def __init__(self, parent: tk.Misc, title: str, color: str) -> None:
        super().__init__(parent, style="Card.TFrame", padding=18)
        ttk.Label(self, text=title, style="CardTitle.TLabel").pack(anchor="w")
        self.value_label = ttk.Label(self, text="—", style="Metric.TLabel")
        self.value_label.pack(anchor="w", pady=(7, 3))
        self.detail_label = ttk.Label(self, text="", style="CardDetail.TLabel")
        self.detail_label.pack(anchor="w")
        self.progress = ttk.Progressbar(
            self,
            mode="determinate",
            maximum=100,
            style=f"{color}.Horizontal.TProgressbar",
        )
        self.progress.pack(fill="x", pady=(14, 0))

    def update_metric(self, value: str, detail: str, percent: float) -> None:
        self.value_label.configure(text=value)
        self.detail_label.configure(text=detail)
        self.progress.configure(value=max(0.0, min(percent, 100.0)))


class SystemInfoApp(tk.Tk):
    REFRESH_MS = 1_500
    CONNECTION_REFRESH_MS = 5_000
    HISTORY_REFRESH_MS = 10_000

    def __init__(
        self,
        database_path: str | Path | None = None,
        settings_store: SettingsStore | None = None,
    ) -> None:
        data_dir = Path(database_path).parent if database_path else get_app_data_dir()
        self.settings_store = settings_store or SettingsStore(data_dir)
        language = self.settings_store.load()["language"]
        self.i18n = configure_i18n(language)
        self._migration_error: str | None = None
        if database_path is None:
            try:
                migrate_legacy_database(get_legacy_app_data_dir(), data_dir)
            except LegacyDataMigrationError as exc:
                self._migration_error = str(exc)

        super().__init__()
        self.title(t("product.window_title"))
        self.geometry("1280x840")
        self.minsize(1000, 700)
        self.configure(bg="#0f172a")

        self._closing = False
        self._shutdown_event = threading.Event()
        self._background_threads: list[threading.Thread] = []

        self._connection_queue: queue.Queue[
            tuple[NetworkSnapshot, dict[str, Any]]
        ] = queue.Queue()
        self._connection_worker_running = False
        self._last_connection_refresh = 0.0
        self._all_connections: list[Connection] = []
        self._displayed_connections: dict[str, Connection] = {}
        self._connection_tracker = ConnectionEventTracker()

        self._history_results: queue.Queue[
            tuple[
                int,
                list[dict[str, Any]],
                list[dict[str, Any]],
                list[dict[str, Any]],
                str | None,
            ]
        ] = queue.Queue()
        self._export_results: queue.Queue[tuple[bool, str]] = queue.Queue()
        self._history_measurements: list[dict[str, Any]] = []
        self._all_history_events: list[dict[str, Any]] = []
        self._all_process_history_events: list[dict[str, Any]] = []
        self._history_generation = 0
        self._history_query_running = False
        self._history_refresh_pending = False
        self._export_running = False
        self._network_messages: queue.Queue[tuple[str, bool]] = queue.Queue()
        self._dns_lock = threading.Lock()
        self._dns_inflight: set[str] = set()
        self._detection_results: queue.Queue[
            tuple[dict[str, Any] | None, str | None]
        ] = queue.Queue()
        self._detection_actions: queue.Queue[
            tuple[bool, str, bool]
        ] = queue.Queue()
        self._detection_query_running = False
        self._detection_error: str | None = None

        self.process_collector = ProcessCollector()
        self._process_event_tracker = ProcessEventTracker()
        self._process_queue: queue.Queue[list[ProcessRecord]] = queue.Queue()
        self._process_detail_queue: queue.Queue[
            tuple[str, ProcessRecord]
        ] = queue.Queue()
        self._process_worker_running = False
        self._process_detail_windows: dict[str, ProcessDetailWindow] = {}

        self._metrics_job: str | None = None
        self._connection_job: str | None = None
        self._connection_poll_job: str | None = None
        self._background_poll_job: str | None = None
        self._history_auto_job: str | None = None
        self._process_job: str | None = None
        self._process_poll_job: str | None = None
        self._detection_refresh_job: str | None = None
        self._root_frame: ttk.Frame | None = None
        self._flag_images: dict[str, tk.PhotoImage] = {}

        self.database = HistoryDatabase(database_path or get_database_path())
        self._database_error: str | None = None
        try:
            self.database.initialize()
        except DatabaseError as exc:
            self._database_error = str(exc)

        self.history_service = HistoryService(self.database)
        self.network_repository = NetworkRepository(self.database)
        self.network_analyzer = NetworkAnalyzer(self.network_repository)
        self.dns_resolver = DnsResolverCache(self.database)
        self.alert_repository = AlertRepository(self.database)
        self.detection_service: DetectionService | None = None
        self.detection_worker: DetectionWorker | None = None
        if self._database_error is None:
            try:
                self.detection_service = DetectionService(self.alert_repository)
                self.detection_worker = DetectionWorker(self.detection_service)
            except Exception as exc:
                self._detection_error = f"Tespit sistemi başlatılamadı: {exc}"

        self._configure_styles()
        self._build_layout()
        self._language_unsubscribe = self.i18n.subscribe(self._language_changed)
        self.protocol("WM_DELETE_WINDOW", self._close)

        if self._database_error is None:
            self.history_service.start()
            if self.detection_worker is not None:
                self.detection_worker.start()
        else:
            self.history_status_label.configure(
                text=t("messages.database_unavailable", error=self._database_error)
            )
        if self._migration_error:
            self.after(
                100,
                lambda: messagebox.showwarning(
                    PRODUCT_NAME,
                    t("messages.migration_failed", error=self._migration_error),
                    parent=self,
                ),
            )

        self._metrics_job = self.after(100, self._refresh_metrics)
        self._connection_job = self.after(200, self._request_connection_refresh)
        self._connection_poll_job = self.after(250, self._poll_connection_results)
        self._background_poll_job = self.after(300, self._poll_background_results)
        self._process_job = self.after(400, self._request_process_refresh)
        self._process_poll_job = self.after(350, self._poll_process_results)
        self._history_auto_job = self.after(
            self.HISTORY_REFRESH_MS, self._history_auto_refresh
        )
        self._detection_refresh_job = self.after(
            700, self._request_detection_refresh
        )

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Root.TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#1e293b", relief="flat")
        style.configure(
            "Title.TLabel",
            background="#0f172a",
            foreground="#f8fafc",
            font=("Segoe UI Semibold", 23),
        )
        style.configure(
            "Subtitle.TLabel",
            background="#0f172a",
            foreground="#94a3b8",
            font=("Segoe UI", 10),
        )
        style.configure(
            "CardTitle.TLabel",
            background="#1e293b",
            foreground="#94a3b8",
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "Metric.TLabel",
            background="#1e293b",
            foreground="#f8fafc",
            font=("Segoe UI Semibold", 21),
        )
        style.configure(
            "CardDetail.TLabel",
            background="#1e293b",
            foreground="#cbd5e1",
            font=("Segoe UI", 9),
        )
        style.configure(
            "Section.TLabel",
            background="#0f172a",
            foreground="#e2e8f0",
            font=("Segoe UI Semibold", 13),
        )
        style.configure(
            "Status.TLabel",
            background="#0f172a",
            foreground="#64748b",
            font=("Segoe UI", 9),
        )
        style.configure(
            "Filter.TLabel",
            background="#0f172a",
            foreground="#cbd5e1",
            font=("Segoe UI", 9),
        )
        style.configure(
            "DetailTitle.TLabel",
            background="#1e293b",
            foreground="#94a3b8",
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "DetailValue.TLabel",
            background="#1e293b",
            foreground="#f8fafc",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Refresh.TButton",
            background="#2563eb",
            foreground="#ffffff",
            padding=(14, 8),
            borderwidth=0,
        )
        style.map("Refresh.TButton", background=[("active", "#1d4ed8")])
        style.configure(
            "Secondary.TButton",
            background="#334155",
            foreground="#f8fafc",
            padding=(12, 7),
            borderwidth=0,
        )
        style.map("Secondary.TButton", background=[("active", "#475569")])
        style.configure(
            "Treeview",
            background="#1e293b",
            fieldbackground="#1e293b",
            foreground="#e2e8f0",
            rowheight=28,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#334155",
            foreground="#f8fafc",
            relief="flat",
            font=("Segoe UI Semibold", 9),
        )
        style.map("Treeview", background=[("selected", "#2563eb")])
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#1e293b",
            foreground="#94a3b8",
            padding=(18, 9),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#2563eb"), ("active", "#334155")],
            foreground=[("selected", "#ffffff"), ("active", "#f8fafc")],
        )
        for name, color in (
            ("blue", "#38bdf8"),
            ("violet", "#a78bfa"),
            ("green", "#34d399"),
        ):
            style.configure(
                f"{name}.Horizontal.TProgressbar",
                troughcolor="#334155",
                background=color,
                bordercolor="#334155",
                lightcolor=color,
                darkcolor=color,
            )

    def _build_layout(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=20)
        self._root_frame = root
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        header = ttk.Frame(root, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=t("product.name"), style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self.computer_label = ttk.Label(header, text="", style="Subtitle.TLabel")
        self.computer_label.grid(row=1, column=0, sticky="w", pady=(3, 0))
        ttk.Button(
            header,
            text=t("common.refresh_now"),
            style="Refresh.TButton",
            command=self._manual_refresh,
        ).grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 12))
        self._build_language_selector(header)

        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=1, column=0, sticky="nsew")
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.overview_tab = ttk.Frame(
            self.notebook, style="Root.TFrame", padding=(4, 16, 4, 4)
        )
        self.history_tab = ttk.Frame(
            self.notebook, style="Root.TFrame", padding=(4, 16, 4, 4)
        )
        self.notebook.add(self.overview_tab, text=t("tabs.overview"))
        self.network_tab = NetworkAnalysisTab(
            self.notebook,
            on_refresh=lambda: self._request_connection_refresh(force=True),
            on_details=self._show_network_details,
            on_finding_status=self._set_network_finding_status,
            on_expected=self._set_network_expected,
            on_dns=self._resolve_network_dns,
        )
        self.notebook.add(self.network_tab, text=t("tabs.network_analysis"))
        self.detection_tab = DetectionTab(
            self.notebook,
            on_refresh=self._request_detection_refresh,
            on_details=self._show_detection_details,
            on_action=self._run_detection_action,
            on_preview=self._preview_detection_rule,
            on_export_all=self._export_detection_all,
        )
        self.notebook.add(self.detection_tab, text=t("tabs.detections"))
        self.processes_tab = ProcessTab(
            self.notebook,
            on_refresh=lambda: self._request_process_refresh(force=True),
            on_open_details=self._open_process_details,
        )
        self.notebook.add(self.processes_tab, text=t("tabs.processes"))
        self.notebook.add(self.history_tab, text=t("tabs.history"))

        self._build_overview_tab()
        self._build_history_tab()

        self.status_label = ttk.Label(root, text="", style="Status.TLabel")
        self.status_label.grid(row=2, column=0, sticky="w", pady=(8, 0))
        localize_widget_tree(root, self.i18n)

    def _build_language_selector(self, parent: ttk.Frame) -> None:
        selector = ttk.Frame(parent, style="Root.TFrame")
        selector.grid(row=0, column=2, rowspan=2, sticky="e")
        for column, (language, _filename, tooltip_key, _fallback) in enumerate(
            (
                ("tr", "tr.png", "header.language_turkish", "TR"),
                ("en", "gb.png", "header.language_english", "EN"),
            )
        ):
            image, fallback_text = load_flag_image(language)
            if image is not None:
                self._flag_images[language] = image
            selected = self.i18n.language == language
            button = tk.Button(
                selector,
                image=image,
                text=fallback_text,
                width=32 if image is not None else 3,
                height=22 if image is not None else 1,
                compound="center",
                command=lambda code=language: self._select_language(code),
                background="#1e293b",
                activebackground="#334155",
                foreground="#f8fafc",
                activeforeground="#ffffff",
                relief="solid",
                borderwidth=2 if selected else 1,
                highlightthickness=2,
                highlightcolor="#38bdf8",
                highlightbackground="#38bdf8" if selected else "#475569",
                takefocus=True,
                cursor="hand2",
            )
            button.grid(row=0, column=column, padx=(0 if column == 0 else 5, 0))
            Tooltip(button, t(tooltip_key))

    def _select_language(self, language: str) -> None:
        if language == self.i18n.language:
            return
        try:
            self.settings_store.save_language(language)
        except OSError as exc:
            messagebox.showerror(PRODUCT_NAME, str(exc), parent=self)
            return
        self.i18n.set_language(language)

    def _language_changed(self, _language: str) -> None:
        if self._closing:
            return
        for child in list(self.winfo_children()):
            if isinstance(child, tk.Toplevel):
                child.destroy()
        if self._root_frame is not None:
            self._root_frame.destroy()
        self._flag_images.clear()
        self.title(t("product.window_title"))
        self._build_layout()
        self.after_idle(self._manual_refresh)
        self.after_idle(lambda: self._request_connection_refresh(force=True))
        self.after_idle(lambda: self._request_process_refresh(force=True))
        self.after_idle(self._request_detection_refresh)

    def _build_overview_tab(self) -> None:
        parent = self.overview_tab
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        cards = ttk.Frame(parent, style="Root.TFrame")
        cards.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        for column in range(3):
            cards.columnconfigure(column, weight=1, uniform="cards")

        self.cpu_card = MetricCard(cards, t("dashboard.cpu_usage"), "blue")
        self.cpu_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.memory_card = MetricCard(cards, t("dashboard.ram_usage"), "violet")
        self.memory_card.grid(row=0, column=1, sticky="nsew", padx=8)
        self.disk_card = MetricCard(cards, t("dashboard.disk_usage"), "green")
        self.disk_card.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        section_header = ttk.Frame(parent, style="Root.TFrame")
        section_header.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        section_header.columnconfigure(0, weight=1)
        ttk.Label(
            section_header, text=t("tabs.active_connections"), style="Section.TLabel"
        ).grid(row=0, column=0, sticky="w")
        self.connection_count_label = ttk.Label(
            section_header, text=t("common.scanning"), style="Status.TLabel"
        )
        self.connection_count_label.grid(row=0, column=1, sticky="e")

        filters = ttk.Frame(section_header, style="Root.TFrame")
        filters.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 2))
        filters.columnconfigure(3, weight=1)
        ttk.Label(filters, text=t("dashboard.protocol"), style="Filter.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 7)
        )
        self.protocol_filter_var = tk.StringVar(value="")
        protocol_filter = ttk.Combobox(
            filters,
            textvariable=self.protocol_filter_var,
            values=(t("common.all"), "TCP", "UDP"),
            state="readonly",
            width=10,
        )
        protocol_filter.grid(row=0, column=1, sticky="w", padx=(0, 22))
        protocol_filter.bind("<<ComboboxSelected>>", self._apply_connection_filters)
        self.protocol_filter_var.set(t("common.all"))
        ttk.Label(filters, text=t("dashboard.process_search"), style="Filter.TLabel").grid(
            row=0, column=2, sticky="w", padx=(0, 7)
        )
        self.process_search_var = tk.StringVar()
        process_search = ttk.Entry(
            filters, textvariable=self.process_search_var, width=32
        )
        process_search.grid(row=0, column=3, sticky="ew")
        process_search.bind("<KeyRelease>", self._apply_connection_filters)

        table_frame = ttk.Frame(parent, style="Card.TFrame", padding=1)
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = (
            "protocol",
            "local_ip",
            "local_port",
            "remote_ip",
            "remote_port",
            "status",
            "pid",
            "process_name",
        )
        self.connection_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "protocol": t("columns.protocol"),
            "local_ip": t("columns.local_ip"),
            "local_port": t("columns.local_port"),
            "remote_ip": t("columns.remote_ip"),
            "remote_port": t("columns.remote_port"),
            "status": t("columns.status"),
            "pid": t("columns.pid"),
            "process_name": t("columns.process_name"),
        }
        widths = {
            "protocol": 75,
            "local_ip": 145,
            "local_port": 85,
            "remote_ip": 145,
            "remote_port": 85,
            "status": 90,
            "pid": 70,
            "process_name": 175,
        }
        for column in columns:
            self.connection_tree.heading(column, text=headings[column])
            self.connection_tree.column(
                column,
                width=widths[column],
                minwidth=70,
                anchor=(
                    "center"
                    if column
                    in {"protocol", "local_port", "remote_port", "status", "pid"}
                    else "w"
                ),
            )
        self._attach_tree_scrollbars(table_frame, self.connection_tree)
        self.connection_tree.bind("<Double-1>", self._show_connection_details)

    def _build_history_tab(self) -> None:
        parent = self.history_tab
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        controls = ttk.Frame(parent, style="Root.TFrame")
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        controls.columnconfigure(2, weight=1)
        ttk.Label(controls, text=t("common.date_range"), style="Filter.TLabel").grid(
            row=0, column=0, padx=(0, 7)
        )
        self._history_range_codes = {
            t(f"history.{code}"): code for code in HISTORY_RANGES
        }
        self.history_range_var = tk.StringVar(value=t("history.last_1_hour"))
        range_combo = ttk.Combobox(
            controls,
            textvariable=self.history_range_var,
            values=tuple(self._history_range_codes),
            state="readonly",
            width=18,
        )
        range_combo.grid(row=0, column=1, sticky="w")
        range_combo.bind("<<ComboboxSelected>>", self._request_history_refresh)
        ttk.Button(
            controls,
            text=t("common.refresh"),
            style="Secondary.TButton",
            command=self._request_history_refresh,
        ).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(
            controls,
            text=t("common.export_csv"),
            style="Secondary.TButton",
            command=lambda: self._choose_export("csv"),
        ).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(
            controls,
            text=t("common.export_json"),
            style="Refresh.TButton",
            command=lambda: self._choose_export("json"),
        ).grid(row=0, column=5, padx=(8, 0))

        self.history_views = ttk.Notebook(parent)
        self.history_views.grid(row=1, column=0, sticky="nsew")
        measurement_view = ttk.Frame(
            self.history_views, style="Root.TFrame", padding=12
        )
        connection_view = ttk.Frame(
            self.history_views, style="Root.TFrame", padding=12
        )
        process_view = ttk.Frame(
            self.history_views, style="Root.TFrame", padding=12
        )
        self.history_views.add(measurement_view, text=t("tabs.system_measurements"))
        self.history_views.add(connection_view, text=t("tabs.connection_events"))
        self.history_views.add(process_view, text=t("tabs.process_events"))

        measurement_view.columnconfigure(0, weight=1)
        measurement_view.rowconfigure(0, weight=1)
        charts = ttk.Frame(measurement_view, style="Root.TFrame")
        charts.grid(row=0, column=0, sticky="nsew")
        for column in range(3):
            charts.columnconfigure(column, weight=1, uniform="charts")
        charts.rowconfigure(0, weight=1)
        self.cpu_history_chart = HistoryChart(
            charts, t("history.cpu_chart"), "cpu_percent", "#38bdf8", 100
        )
        self.cpu_history_chart.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.ram_history_chart = HistoryChart(
            charts, t("history.ram_chart"), "ram_percent", "#a78bfa", 100
        )
        self.ram_history_chart.grid(row=0, column=1, sticky="nsew", padx=6)
        self.connection_history_chart = HistoryChart(
            charts, t("history.connections_chart"), "active_connections", "#34d399"
        )
        self.connection_history_chart.grid(
            row=0, column=2, sticky="nsew", padx=(6, 0)
        )

        self._build_connection_history_view(connection_view)
        self._build_process_history_view(process_view)

        self.history_status_label = ttk.Label(
            parent,
            text=t("common.loading"),
            style="Status.TLabel",
        )
        self.history_status_label.grid(row=2, column=0, sticky="w", pady=(7, 0))

    def _build_connection_history_view(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        event_header = ttk.Frame(parent, style="Root.TFrame")
        event_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        event_header.columnconfigure(0, weight=1)
        ttk.Label(
            event_header, text=t("tabs.connection_events"), style="Section.TLabel"
        ).grid(row=0, column=0, sticky="w")
        self.history_event_count_label = ttk.Label(
            event_header, text="0 olay", style="Status.TLabel"
        )
        self.history_event_count_label.grid(row=0, column=1, sticky="e")

        event_filters = ttk.Frame(event_header, style="Root.TFrame")
        event_filters.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        event_filters.columnconfigure(1, weight=1)
        ttk.Label(event_filters, text=t("dashboard.process_search"), style="Filter.TLabel").grid(
            row=0, column=0, padx=(0, 7)
        )
        self.history_process_var = tk.StringVar()
        history_search = ttk.Entry(
            event_filters, textvariable=self.history_process_var, width=28
        )
        history_search.grid(row=0, column=1, sticky="ew", padx=(0, 16))
        history_search.bind("<KeyRelease>", self._apply_history_event_filters)

        ttk.Label(event_filters, text=t("columns.event_type"), style="Filter.TLabel").grid(
            row=0, column=2, padx=(0, 7)
        )
        self._connection_event_filter_codes = {
            t("common.all"): "all",
            self.i18n.enum("event_type", "connection_opened"): "connection_opened",
            self.i18n.enum("event_type", "connection_closed"): "connection_closed",
        }
        self.history_event_type_var = tk.StringVar(value=t("common.all"))
        event_combo = ttk.Combobox(
            event_filters,
            textvariable=self.history_event_type_var,
            values=tuple(self._connection_event_filter_codes),
            state="readonly",
            width=11,
        )
        event_combo.grid(row=0, column=3, padx=(0, 16))
        event_combo.bind("<<ComboboxSelected>>", self._apply_history_event_filters)

        ttk.Label(event_filters, text=t("columns.protocol"), style="Filter.TLabel").grid(
            row=0, column=4, padx=(0, 7)
        )
        self.history_protocol_var = tk.StringVar(value=t("common.all"))
        history_protocol = ttk.Combobox(
            event_filters,
            textvariable=self.history_protocol_var,
            values=(t("common.all"), "TCP", "UDP"),
            state="readonly",
            width=10,
        )
        history_protocol.grid(row=0, column=5)
        history_protocol.bind(
            "<<ComboboxSelected>>", self._apply_history_event_filters
        )

        table_frame = ttk.Frame(parent, style="Card.TFrame", padding=1)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = (
            "timestamp",
            "event_type",
            "protocol",
            "pid",
            "process_name",
            "local",
            "remote",
            "status",
        )
        self.history_event_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "timestamp": t("columns.timestamp"),
            "event_type": t("columns.event_type"),
            "protocol": t("columns.protocol"),
            "pid": t("columns.pid"),
            "process_name": t("columns.process_name"),
            "local": t("common.local_address"),
            "remote": t("common.remote_address"),
            "status": t("columns.status"),
        }
        widths = {
            "timestamp": 145,
            "event_type": 85,
            "protocol": 75,
            "pid": 70,
            "process_name": 165,
            "local": 190,
            "remote": 190,
            "status": 90,
        }
        for column in columns:
            self.history_event_tree.heading(column, text=headings[column])
            self.history_event_tree.column(
                column,
                width=widths[column],
                minwidth=65,
                anchor=(
                    "center"
                    if column in {"event_type", "protocol", "pid", "status"}
                    else "w"
                ),
            )
        self._attach_tree_scrollbars(table_frame, self.history_event_tree)

    def _build_process_history_view(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        header = ttk.Frame(parent, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=t("tabs.process_events"), style="Section.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self.process_history_count_label = ttk.Label(
            header, text="0 olay", style="Status.TLabel"
        )
        self.process_history_count_label.grid(row=0, column=1, sticky="e")

        filters = ttk.Frame(header, style="Root.TFrame")
        filters.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        filters.columnconfigure(1, weight=1)
        filters.columnconfigure(7, weight=1)
        ttk.Label(filters, text=t("dashboard.process_search"), style="Filter.TLabel").grid(
            row=0, column=0, padx=(0, 7)
        )
        self.process_history_name_var = tk.StringVar()
        name_entry = ttk.Entry(filters, textvariable=self.process_history_name_var)
        name_entry.grid(row=0, column=1, sticky="ew", padx=(0, 14))
        name_entry.bind("<KeyRelease>", self._apply_process_history_filters)
        ttk.Label(filters, text=t("columns.event_type"), style="Filter.TLabel").grid(
            row=0, column=2, padx=(0, 7)
        )
        self._process_event_filter_codes = {
            t("common.all"): "all",
            self.i18n.enum("event_type", "process_started"): "process_started",
            self.i18n.enum("event_type", "process_stopped"): "process_stopped",
        }
        self.process_history_type_var = tk.StringVar(value=t("common.all"))
        type_combo = ttk.Combobox(
            filters,
            textvariable=self.process_history_type_var,
            values=tuple(self._process_event_filter_codes),
            state="readonly",
            width=11,
        )
        type_combo.grid(row=0, column=3, padx=(0, 14))
        type_combo.bind(
            "<<ComboboxSelected>>", self._apply_process_history_filters
        )
        ttk.Label(filters, text=t("common.user"), style="Filter.TLabel").grid(
            row=0, column=4, padx=(0, 7)
        )
        self.process_history_user_var = tk.StringVar()
        user_entry = ttk.Entry(
            filters, textvariable=self.process_history_user_var, width=18
        )
        user_entry.grid(row=0, column=5, padx=(0, 14))
        user_entry.bind("<KeyRelease>", self._apply_process_history_filters)
        ttk.Label(filters, text=t("common.file_path"), style="Filter.TLabel").grid(
            row=0, column=6, padx=(0, 7)
        )
        self.process_history_path_var = tk.StringVar()
        path_entry = ttk.Entry(filters, textvariable=self.process_history_path_var)
        path_entry.grid(row=0, column=7, sticky="ew")
        path_entry.bind("<KeyRelease>", self._apply_process_history_filters)

        table_frame = ttk.Frame(parent, style="Card.TFrame", padding=1)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = (
            "timestamp",
            "event_type",
            "process_name",
            "pid",
            "parent",
            "username",
            "exe",
        )
        self.process_history_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        labels = {
            "timestamp": t("columns.timestamp"),
            "event_type": t("columns.event_type"),
            "process_name": t("columns.process_name"),
            "pid": t("columns.pid"),
            "parent": t("columns.parent_process_name"),
            "username": t("columns.username"),
            "exe": t("common.file_path"),
        }
        widths = {
            "timestamp": 145,
            "event_type": 85,
            "process_name": 170,
            "pid": 75,
            "parent": 170,
            "username": 160,
            "exe": 320,
        }
        for column in columns:
            self.process_history_tree.heading(column, text=labels[column])
            self.process_history_tree.column(
                column,
                width=widths[column],
                minwidth=65,
                anchor="center" if column in {"event_type", "pid"} else "w",
            )
        self._attach_tree_scrollbars(table_frame, self.process_history_tree)
        self.process_history_tree.bind(
            "<Double-1>", self._show_process_event_details
        )
        self._process_history_records_by_item: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _attach_tree_scrollbars(
        parent: ttk.Frame, tree: ttk.Treeview
    ) -> None:
        vertical = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

    def _refresh_metrics(self) -> None:
        if self._closing:
            return
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            disks = collect_disks()
            main_disk = disks[0] if disks else None
            self.computer_label.configure(
                text=t(
                    "header.computer",
                    hostname=socket.gethostname(),
                    cpu=cpu_name(),
                )
            )
            self.cpu_card.update_metric(
                f"%{cpu_percent:.1f}",
                t(
                    "dashboard.logical_cores",
                    count=psutil.cpu_count(logical=True) or 0,
                ),
                cpu_percent,
            )
            self.memory_card.update_metric(
                f"%{memory.percent:.1f}",
                f"{format_bytes(memory.used)} / {format_bytes(memory.total)}",
                memory.percent,
            )
            if main_disk:
                self.disk_card.update_metric(
                    f"%{main_disk['percent']:.1f}",
                    f"{main_disk['used']} / {main_disk['total']}  •  {main_disk['mountpoint']}",
                    float(main_disk["percent"]),
                )
            else:
                self.disk_card.update_metric("—", "Erişilebilir disk bulunamadı", 0)
            self.status_label.configure(
                text=t("dashboard.last_update", time=f"{datetime.now():%H:%M:%S}")
            )
        except (OSError, RuntimeError) as exc:
            self.status_label.configure(text=f"Sistem bilgileri okunamadı: {exc}")
        self._metrics_job = self.after(self.REFRESH_MS, self._refresh_metrics)

    def _manual_refresh(self) -> None:
        self._cancel_job("_metrics_job")
        self._refresh_metrics()
        self._request_connection_refresh(force=True)
        if self.notebook.select() == str(self.history_tab):
            self._request_history_refresh()

    def _request_connection_refresh(self, force: bool = False) -> None:
        if force:
            self._cancel_job("_connection_job")
        if self._closing or self._connection_worker_running:
            return
        now = datetime.now().timestamp()
        if not force and now - self._last_connection_refresh < 4.0:
            return
        self._connection_worker_running = True
        self.connection_count_label.configure(text="Taranıyor…")
        process_records = (
            list(self.processes_tab._all_records)
            if hasattr(self, "processes_tab")
            else []
        )
        self._start_background_worker(
            lambda: self._collect_connections_worker(process_records),
            "connection-reader",
        )

    def _collect_connections_worker(
        self, process_records: list[ProcessRecord]
    ) -> None:
        snapshot = collect_network_snapshot(process_records=process_records)
        try:
            analysis = self.network_analyzer.process(snapshot)
        except Exception as exc:
            analysis = {
                "listeners": [],
                "endpoints": [],
                "events": [],
                "findings": [],
                "event_count_24h": 0,
                "error": str(exc),
            }
        self._connection_queue.put((snapshot, analysis))

    def _poll_connection_results(self) -> None:
        if self._closing:
            return
        try:
            snapshot, analysis = self._connection_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            connections = [dict(item) for item in snapshot.connections]
            self._connection_worker_running = False
            self._last_connection_refresh = datetime.now().timestamp()
            self._display_connections(connections)
            self.history_service.set_active_connection_count(len(connections))
            events = self._connection_tracker.update(connections)
            self.history_service.record_connection_events(events)
            self.network_tab.set_data(connections, analysis)
            if analysis.get("error"):
                self.status_label.configure(
                    text=f"Ağ analizi güncellenemedi: {analysis['error']}"
                )
            self._connection_job = self.after(
                self.CONNECTION_REFRESH_MS, self._request_connection_refresh
            )
        self._connection_poll_job = self.after(250, self._poll_connection_results)

    def _show_network_details(
        self, record: dict[str, Any], kind: str
    ) -> None:
        details = dict(record)
        pid = str(record.get("pid", record.get("last_pid", "—")))
        related_connections = [
            item for item in self._all_connections if str(item.get("pid")) == pid
        ]
        if related_connections:
            details["ilgili_aktif_bağlantılar"] = related_connections
        process_records = (
            list(self.processes_tab._all_records)
            if hasattr(self, "processes_tab")
            else []
        )
        related_processes = [
            item for item in process_records if str(item.get("pid")) == pid
        ]
        if related_processes:
            process_record = related_processes[0]
            details["ilgili_işlem"] = process_record
            parent_pid = str(process_record.get("parent_pid", "—"))
            details["parent_işlem"] = next(
                (
                    item
                    for item in process_records
                    if str(item.get("pid")) == parent_pid
                ),
                None,
            )
            details["alt_işlemler"] = [
                item
                for item in process_records
                if str(item.get("parent_pid")) == pid
            ]
        related_process_events = [
            item
            for item in self._all_process_history_events
            if str(item.get("pid")) == pid
        ]
        if related_process_events:
            details["ilgili_işlem_olayları"] = related_process_events
        if kind == "listener":
            details["aynı_işlemin_diğer_dinleyicileri"] = [
                item
                for item in self.network_tab.data.get("listeners", [])
                if str(item.get("pid")) == pid
                and item.get("identity_key") != record.get("identity_key")
            ]
            details["ilgili_ağ_olayları"] = [
                item
                for item in self.network_tab.data.get("events", [])
                if item.get("local_ip") == record.get("local_ip")
                and str(item.get("local_port")) == str(record.get("local_port"))
            ]
        if kind == "endpoint":
            remote_ip, remote_port = record.get("remote_ip"), record.get("remote_port")
            details["ilgili_bulgular"] = [
                item
                for item in self.network_tab.data.get("findings", [])
                if str(remote_ip) in str(item.get("remote_address"))
            ]
            details["ilgili_aktif_bağlantılar"] = [
                item
                for item in self._all_connections
                if item.get("remote_ip") == remote_ip
                and str(item.get("remote_port")) == str(remote_port)
            ]
            details["ilgili_ağ_olayları"] = [
                item
                for item in self.network_tab.data.get("events", [])
                if item.get("remote_ip") == remote_ip
                and str(item.get("remote_port")) == str(remote_port)
            ]
        if kind in {"event", "finding"}:
            local_address = str(record.get("local_address", ""))
            remote_address = str(record.get("remote_address", ""))
            details["ilgili_ağ_olayları"] = [
                item
                for item in self.network_tab.data.get("events", [])
                if str(item.get("pid")) == pid
                or (
                    item.get("remote_ip")
                    and str(item.get("remote_ip")) in remote_address
                )
                or (
                    item.get("local_ip")
                    and str(item.get("local_ip")) in local_address
                )
            ][:100]
        NetworkDetailWindow(self, details, kind)

    def _set_network_finding_status(self, finding_id: int, status: str) -> None:
        def worker() -> None:
            try:
                self.network_repository.set_finding_status(finding_id, status)
                self._network_messages.put((f"Bulgu durumu: {status}", True))
            except Exception as exc:
                self._network_messages.put((f"Bulgu güncellenemedi: {exc}", False))
        self._start_background_worker(worker, "network-finding-update")

    def _set_network_expected(
        self, kind: str, record_id: str | int, expected: bool, note: str
    ) -> None:
        def worker() -> None:
            try:
                self.network_repository.set_expected(
                    kind, record_id, expected, note
                )
                text = "Beklenen baseline işareti güncellendi."
                self._network_messages.put((text, True))
            except Exception as exc:
                self._network_messages.put((f"Baseline güncellenemedi: {exc}", False))
        self._start_background_worker(worker, "network-baseline-update")

    def _resolve_network_dns(self, ip_address: str) -> None:
        if self._closing:
            return
        with self._dns_lock:
            if ip_address in self._dns_inflight:
                self.status_label.configure(
                    text=f"{ip_address} için çözümleme zaten sürüyor."
                )
                return
            if len(self._dns_inflight) >= 2:
                self.status_label.configure(
                    text="En fazla iki ters DNS çözümlemesi aynı anda çalışabilir."
                )
                return
            self._dns_inflight.add(ip_address)

        def worker() -> None:
            try:
                hostname = self.dns_resolver.resolve(ip_address)
                self._network_messages.put(
                    (f"{ip_address} → {hostname}", True)
                )
            except Exception as exc:
                self._network_messages.put(
                    (f"Ters DNS çözümlenemedi: {exc}", False)
                )
            finally:
                with self._dns_lock:
                    self._dns_inflight.discard(ip_address)
        self._start_background_worker(worker, "reverse-dns")

    def _request_process_refresh(self, force: bool = False) -> None:
        if force:
            self._cancel_job("_process_job")
        if self._closing or self._process_worker_running:
            return
        self._process_worker_running = True
        counts: dict[int, int] = {}
        for connection in self._all_connections:
            pid = connection.get("pid")
            if isinstance(pid, int):
                counts[pid] = counts.get(pid, 0) + 1

        def worker() -> None:
            try:
                records = self.process_collector.collect_processes(
                    network_counts=counts
                )
            except Exception:
                records = []
            self._process_queue.put(records)

        self._start_background_worker(worker, "process-reader")

    def _poll_process_results(self) -> None:
        if self._closing:
            return
        try:
            processes = self._process_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self._process_worker_running = False
            self.processes_tab.set_processes(processes)
            events = self._process_event_tracker.update(processes)
            self.history_service.record_process_events(events)
            self._process_job = self.after(
                int(PROCESS_REFRESH_INTERVAL_SECONDS * 1000),
                self._request_process_refresh,
            )
        self._process_poll_job = self.after(250, self._poll_process_results)

    def _open_process_details(self, record: ProcessRecord) -> None:
        token = uuid.uuid4().hex
        window: ProcessDetailWindow
        window = ProcessDetailWindow(
            self,
            record,
            on_refresh=lambda: self._request_process_details(token, window.record),
        )
        self._process_detail_windows[token] = window
        self._request_process_details(token, record)

    def _request_process_details(
        self, token: str, record: ProcessRecord
    ) -> None:
        window = self._process_detail_windows.get(token)
        if window is None or not window.winfo_exists():
            return
        window.set_loading()
        connections = list(self._all_connections)
        identity = process_identity(record)
        latest = next(
            (
                item
                for item in self.processes_tab._all_records
                if process_identity(item) == identity
            ),
            record,
        )
        record_copy = dict(latest)

        def worker() -> None:
            try:
                collector = ProcessCollector()
                details = collector.collect_details(record_copy, connections)
            except Exception:
                details = {
                    **record_copy,
                    "status": "unknown",
                    "uptime": t("common.unknown"),
                    "open_files_count": t("common.unknown"),
                    "children": [],
                    "parent_chain": [],
                    "connections": [],
                }
            self._process_detail_queue.put((token, details))

        self._start_background_worker(worker, "process-detail-reader")

    def _poll_process_detail_results(self) -> None:
        while True:
            try:
                token, details = self._process_detail_queue.get_nowait()
            except queue.Empty:
                break
            window = self._process_detail_windows.get(token)
            if window is not None and window.winfo_exists():
                window.update_details(details)
            else:
                self._process_detail_windows.pop(token, None)

    def _display_connections(self, connections: list[Connection]) -> None:
        self._all_connections = connections
        self._apply_connection_filters()

    def _apply_connection_filters(self, _event: tk.Event | None = None) -> None:
        connections = filter_connections(
            self._all_connections,
            protocol=(
                "all"
                if self.protocol_filter_var.get() == t("common.all")
                else self.protocol_filter_var.get()
            ),
            process_query=self.process_search_var.get(),
        )
        self.connection_tree.delete(*self.connection_tree.get_children())
        self._displayed_connections.clear()
        for connection in connections:
            item_id = self.connection_tree.insert(
                "",
                "end",
                values=(
                    connection["protocol"],
                    connection["local_ip"],
                    connection["local_port"],
                    connection["remote_ip"],
                    connection["remote_port"],
                    self.i18n.enum("network_status", connection["status"]),
                    connection["pid"],
                    connection["process_name"],
                ),
            )
            self._displayed_connections[item_id] = connection
        if len(connections) == len(self._all_connections):
            text = t("dashboard.active_connections", count=len(connections))
        else:
            text = t(
                "dashboard.connection_filtered",
                shown=len(connections),
                total=len(self._all_connections),
            )
        self.connection_count_label.configure(text=text)

    def _show_connection_details(self, event: tk.Event) -> None:
        item_id = self.connection_tree.identify_row(event.y)
        connection = self._displayed_connections.get(item_id)
        if connection is None:
            return
        self.connection_tree.selection_set(item_id)
        window = tk.Toplevel(self)
        window.title(t("connections.details_title"))
        window.geometry("460x440")
        window.resizable(False, False)
        window.configure(bg="#1e293b")
        window.transient(self)
        content = ttk.Frame(window, style="Card.TFrame", padding=24)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)
        fields = (
            ("İşlem adı", connection["process_name"]),
            ("PID", connection["pid"]),
            ("Protokol", connection["protocol"]),
            (t("columns.status"), self.i18n.enum("network_status", connection["status"])),
            ("Yerel IP", connection["local_ip"]),
            ("Yerel port", connection["local_port"]),
            ("Uzak IP", connection["remote_ip"]),
            ("Uzak port", connection["remote_port"]),
        )
        for row, (label, value) in enumerate(fields):
            ttk.Label(content, text=label, style="DetailTitle.TLabel").grid(
                row=row, column=0, sticky="nw", padx=(0, 24), pady=8
            )
            ttk.Label(
                content,
                text=str(value),
                style="DetailValue.TLabel",
                wraplength=270,
            ).grid(row=row, column=1, sticky="nw", pady=8)
        ttk.Button(
            content, text="Kapat", style="Refresh.TButton", command=window.destroy
        ).grid(row=len(fields), column=0, columnspan=2, sticky="e", pady=(18, 0))
        localize_widget_tree(window, self.i18n)

    def _on_tab_changed(self, _event: tk.Event | None = None) -> None:
        if (
            hasattr(self, "history_tab")
            and self.notebook.select() == str(self.history_tab)
        ):
            self._request_history_refresh()
        if (
            hasattr(self, "detection_tab")
            and self.notebook.select() == str(self.detection_tab)
        ):
            self._request_detection_refresh()

    def _request_detection_refresh(self) -> None:
        self._cancel_job("_detection_refresh_job")
        if (
            self._closing
            or self._database_error is not None
            or self._detection_query_running
        ):
            return
        self._detection_query_running = True

        def worker() -> None:
            try:
                data = self.alert_repository.dashboard()
                error = None
            except Exception as exc:
                data = None
                error = f"Tespit verileri okunamadı: {exc}"
            self._detection_results.put((data, error))

        self._start_background_worker(worker, "detection-dashboard-reader")

    def _show_detection_details(
        self,
        record: dict[str, Any],
        kind: str,
    ) -> None:
        try:
            if kind == "alert":
                details = self.alert_repository.alert_details(int(record["id"]))
                AlertDetailWindow(
                    self,
                    details,
                    lambda alert_id, status, note: self._run_detection_action(
                        "alert_status",
                        {"id": alert_id, "status": status, "note": note},
                    ),
                    lambda alert_id, note: self._run_detection_action(
                        "alert_note",
                        {"id": alert_id, "note": note},
                    ),
                    lambda alert_id: self._create_case_for_alert(alert_id),
                    self._export_single_alert,
                )
            elif kind == "case":
                details = self.alert_repository.case_details(int(record["id"]))
                CaseDetailWindow(
                    self,
                    details,
                    lambda case_id, values: self._run_detection_action(
                        "case_update",
                        {"id": case_id, **values},
                    ),
                    lambda case_id, note: self._run_detection_action(
                        "case_note",
                        {"id": case_id, "note": note},
                    ),
                    lambda case_id, alert_id: self._run_detection_action(
                        "case_remove_alert",
                        {"case_id": case_id, "alert_id": alert_id},
                    ),
                    self._export_single_case,
                )
            elif kind == "rule":
                readonly = bool(record.get("_metadata", {}).get("is_builtin"))
                RuleEditorWindow(
                    self,
                    record,
                    readonly,
                    lambda rule: self._run_detection_action(
                        "rule_save",
                        {"rule": rule},
                    ),
                    self._preview_detection_rule,
                )
            else:
                NetworkDetailWindow(self, record, kind)
        except Exception as exc:
            messagebox.showerror("Tespit ayrıntısı", str(exc), parent=self)

    def _run_detection_action(
        self,
        action: str,
        payload: dict[str, Any],
    ) -> None:
        if self.detection_service is None:
            messagebox.showerror(
                "Tespit sistemi",
                self._detection_error or "Tespit sistemi kullanılamıyor.",
                parent=self,
            )
            return

        def worker() -> None:
            try:
                if action == "alert_status":
                    self.alert_repository.set_alert_status(
                        int(payload["id"]),
                        str(payload["status"]),
                        str(payload.get("note", "")),
                    )
                elif action == "alert_note":
                    self.alert_repository.add_alert_note(
                        int(payload["id"]),
                        str(payload["note"]),
                    )
                elif action == "case_create":
                    self.alert_repository.create_case(
                        str(payload["title"]),
                        str(payload.get("description", "")),
                        str(payload.get("severity", "info")),
                        [int(item) for item in payload.get("alert_ids", [])],
                    )
                elif action == "case_add_alert":
                    self.alert_repository.add_alert_to_case(
                        int(payload["case_id"]),
                        int(payload["alert_id"]),
                    )
                elif action == "case_remove_alert":
                    self.alert_repository.remove_alert_from_case(
                        int(payload["case_id"]),
                        int(payload["alert_id"]),
                    )
                elif action == "case_update":
                    self.alert_repository.update_case(
                        int(payload["id"]),
                        title=payload.get("title"),
                        description=payload.get("description"),
                        severity=payload.get("severity"),
                        status=payload.get("status"),
                        conclusion=payload.get("conclusion"),
                    )
                elif action == "case_note":
                    self.alert_repository.add_case_note(
                        int(payload["id"]),
                        str(payload["note"]),
                    )
                elif action == "rule_toggle":
                    self.alert_repository.set_rule_enabled(
                        str(payload["id"]),
                        bool(payload["enabled"]),
                    )
                elif action == "rule_save":
                    self.alert_repository.save_user_rule(payload["rule"])
                elif action == "rule_delete":
                    self.alert_repository.delete_user_rule(str(payload["id"]))
                elif action == "suppression_create":
                    _, broad = self.detection_service.suppressions.create(
                        str(payload["name"]),
                        payload["conditions"],
                        str(payload["reason"]),
                        payload.get("expires_at"),
                    )
                    if broad:
                        self._detection_actions.put(
                            (
                                True,
                                "Geniş kapsamlı susturma oluşturuldu; kapsamını düzenli olarak gözden geçirin.",
                                True,
                            )
                        )
                        return
                elif action == "suppression_toggle":
                    self.alert_repository.set_suppression_enabled(
                        int(payload["id"]),
                        bool(payload["enabled"]),
                    )
                elif action == "suppression_delete":
                    self.alert_repository.delete_suppression(int(payload["id"]))
                else:
                    raise ValueError(f"Unsupported detection action: {action}")
                self._detection_actions.put((True, "Tespit kaydı güncellendi.", True))
            except Exception as exc:
                self._detection_actions.put(
                    (False, f"Tespit işlemi başarısız: {exc}", False)
                )

        self._start_background_worker(worker, f"detection-action-{action}")

    def _preview_detection_rule(
        self,
        rule: dict[str, Any],
        since: datetime,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        if self.detection_service is None:
            raise RuntimeError(self._detection_error or "Detection system is unavailable")
        return self.detection_service.preview_rule(rule, since, until=until)

    def _create_case_for_alert(self, alert_id: int) -> None:
        self._run_detection_action(
            "case_create",
            {
                "title": f"Alarm {alert_id} incelemesi",
                "description": "Alarm ayrıntısından oluşturuldu.",
                "severity": "medium",
                "alert_ids": [alert_id],
            },
        )

    def _export_detection_all(self, file_format: str) -> None:
        extension = f".{file_format}"
        path = filedialog.asksaveasfilename(
            parent=self,
            title=t("common.export"),
            defaultextension=extension,
            initialfile=(
                f"{PRODUCT_SLUG}_detections_{datetime.now():%Y-%m-%d}{extension}"
            ),
            filetypes=[(file_format.upper(), f"*{extension}")],
        )
        if not path:
            return
        exporter = export_detection_csv if file_format == "csv" else export_detection_json

        def worker() -> None:
            try:
                exporter(path, self.alert_repository)
                self._detection_actions.put(
                    (True, f"Tespit verileri kaydedildi: {path}", False)
                )
            except Exception as exc:
                self._detection_actions.put(
                    (False, f"Tespit dışa aktarma başarısız: {exc}", False)
                )

        self._start_background_worker(worker, "detection-exporter")

    def _export_single_alert(self, alert_id: int) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="Alarm raporunu dışa aktar",
            initialfile=f"{PRODUCT_SLUG}_alert_{alert_id}_{datetime.now():%Y-%m-%d}.json",
        )
        if path:
            self._start_background_worker(
                lambda: self._safe_single_export(
                    export_single_alert_json,
                    path,
                    alert_id,
                ),
                "alert-exporter",
            )

    def _export_single_case(self, case_id: int) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="Olay raporunu dışa aktar",
            initialfile=f"{PRODUCT_SLUG}_case_{case_id}_{datetime.now():%Y-%m-%d}.json",
        )
        if path:
            self._start_background_worker(
                lambda: self._safe_single_export(
                    export_single_case_json,
                    path,
                    case_id,
                ),
                "case-exporter",
            )

    def _safe_single_export(
        self,
        exporter: Callable[[str, AlertRepository, int], None],
        path: str,
        record_id: int,
    ) -> None:
        try:
            exporter(path, self.alert_repository, record_id)
            self._detection_actions.put((True, f"Rapor kaydedildi: {path}", False))
        except Exception as exc:
            self._detection_actions.put((False, f"Rapor kaydedilemedi: {exc}", False))

    def _request_history_refresh(self, _event: tk.Event | None = None) -> None:
        if self._database_error is not None or self._closing:
            return
        self._history_generation += 1
        if self._history_query_running:
            self._history_refresh_pending = True
            return
        self._start_history_query(self._history_generation)

    def _start_history_query(self, generation: int) -> None:
        self._history_query_running = True
        self.history_status_label.configure(text="Geçmiş verileri yükleniyor…")
        range_code = self._history_range_codes.get(
            self.history_range_var.get(), "last_1_hour"
        )
        seconds = HISTORY_RANGES.get(range_code, HISTORY_RANGES["last_1_hour"])
        since = datetime.now(timezone.utc) - timedelta(seconds=seconds)

        def worker() -> None:
            try:
                measurements = self.database.query_measurements(since)
                events = self.database.query_connection_events(since, limit=2_000)
                process_events = self.database.query_process_events(
                    since, limit=2_000
                )
                error = None
            except Exception as exc:
                measurements, events, process_events = [], [], []
                error = f"Geçmiş okunamadı: {exc}"
            self._history_results.put(
                (generation, measurements, events, process_events, error)
            )

        self._start_background_worker(worker, "history-reader")

    def _apply_history_data(
        self,
        measurements: list[dict[str, Any]],
        events: list[dict[str, Any]],
        process_events: list[dict[str, Any]],
    ) -> None:
        self._history_measurements = measurements
        self._all_history_events = events
        self._all_process_history_events = process_events
        self.cpu_history_chart.set_data(measurements)
        self.ram_history_chart.set_data(measurements)
        self.connection_history_chart.set_data(measurements)
        self._apply_history_event_filters()
        self._apply_process_history_filters()
        if measurements or events or process_events:
            self.history_status_label.configure(
                text=(
                    f"{len(measurements)} ölçüm, {len(events)} bağlantı ve "
                    f"{len(process_events)} işlem olayı "
                    f"yüklendi • {datetime.now():%H:%M:%S}"
                )
            )
        else:
            self.history_status_label.configure(
                text="Seçilen zaman aralığında henüz geçmiş verisi yok."
            )

    def _apply_history_event_filters(self, _event: tk.Event | None = None) -> None:
        events = filter_connection_events(
            self._all_history_events,
            process_query=self.history_process_var.get(),
            event_type=self._connection_event_filter_codes.get(
                self.history_event_type_var.get(), "all"
            ),
            protocol=(
                "all"
                if self.history_protocol_var.get() == t("common.all")
                else self.history_protocol_var.get()
            ),
        )
        self.history_event_tree.delete(*self.history_event_tree.get_children())
        for event in events:
            self.history_event_tree.insert(
                "",
                "end",
                values=(
                    self._local_timestamp(str(event["timestamp"])),
                    self.i18n.enum("event_type", event["event_type"]),
                    event["protocol"],
                    event["pid"],
                    event["process_name"],
                    f"{event['local_ip']}:{event['local_port']}",
                    f"{event['remote_ip']}:{event['remote_port']}",
                    self.i18n.enum("network_status", event["status"]),
                ),
            )
        if len(events) == len(self._all_history_events):
            text = f"{len(events)} olay"
        else:
            text = f"{len(events)} gösteriliyor / {len(self._all_history_events)} olay"
        self.history_event_count_label.configure(text=text)

    def _apply_process_history_filters(
        self, _event: tk.Event | None = None
    ) -> None:
        events = filter_process_events(
            self._all_process_history_events,
            process_query=self.process_history_name_var.get(),
            event_type=self._process_event_filter_codes.get(
                self.process_history_type_var.get(), "all"
            ),
            username_query=self.process_history_user_var.get(),
            path_query=self.process_history_path_var.get(),
        )
        self.process_history_tree.delete(
            *self.process_history_tree.get_children()
        )
        self._process_history_records_by_item.clear()
        for event in events:
            item_id = self.process_history_tree.insert(
                "",
                "end",
                values=(
                    self._local_timestamp(str(event["timestamp"])),
                    self.i18n.enum("event_type", event["event_type"]),
                    event["process_name"],
                    event["pid"],
                    f"{event['parent_name']} (PID {event['parent_pid']})",
                    event["username"],
                    event["exe"],
                ),
            )
            self._process_history_records_by_item[item_id] = event
        if len(events) == len(self._all_process_history_events):
            text = f"{len(events)} olay"
        else:
            text = (
                f"{len(events)} gösteriliyor / "
                f"{len(self._all_process_history_events)} olay"
            )
        self.process_history_count_label.configure(text=text)

    def _show_process_event_details(self, event: tk.Event) -> None:
        item_id = self.process_history_tree.identify_row(event.y)
        record = self._process_history_records_by_item.get(item_id)
        if record is None:
            return
        window = tk.Toplevel(self)
        window.title("İşlem Olayı Ayrıntıları")
        window.geometry("720x620")
        window.configure(bg="#0f172a")
        window.transient(self)
        content = ttk.Frame(window, style="Root.TFrame", padding=18)
        content.pack(fill="both", expand=True)
        content.columnconfigure(1, weight=1)
        fields = (
            ("Zaman", self._local_timestamp(str(record["timestamp"]))),
            ("Olay türü", record["event_type"]),
            ("İşlem adı", record["process_name"]),
            ("PID", record["pid"]),
            ("Oluşturulma zamanı", record.get("create_time") or "Bilinmiyor"),
            ("Parent PID", record["parent_pid"]),
            ("Parent işlem", record["parent_name"]),
            ("Kullanıcı", record["username"]),
            ("İlk görüldü", self._local_timestamp(str(record["first_seen"]))),
            ("Son görüldü", self._local_timestamp(str(record["last_seen"]))),
        )
        for row, (label, value) in enumerate(fields):
            ttk.Label(content, text=label, style="Filter.TLabel").grid(
                row=row, column=0, sticky="nw", padx=(0, 18), pady=4
            )
            ttk.Label(
                content, text=str(value), style="Subtitle.TLabel"
            ).grid(row=row, column=1, sticky="nw", pady=4)

        row = len(fields)
        for label, key in (("Dosya yolu", "exe"), ("Komut satırı", "command_line")):
            ttk.Label(content, text=label, style="Filter.TLabel").grid(
                row=row, column=0, sticky="nw", padx=(0, 18), pady=(8, 4)
            )
            text = tk.Text(
                content,
                height=3,
                wrap="word",
                background="#1e293b",
                foreground="#e2e8f0",
                selectbackground="#2563eb",
                relief="flat",
                padx=8,
                pady=6,
            )
            text.insert("1.0", str(record.get(key, "Bilinmiyor")))
            text.configure(state="disabled")
            text.grid(row=row, column=1, sticky="ew", pady=(8, 4))
            row += 1
        ttk.Button(
            content, text="Kapat", style="Refresh.TButton", command=window.destroy
        ).grid(row=row, column=0, columnspan=2, sticky="e", pady=(12, 0))

    def _local_timestamp(self, value: str) -> str:
        return format_datetime(value, self.i18n.language)

    def _history_auto_refresh(self) -> None:
        if self._closing:
            return
        if self.notebook.select() == str(self.history_tab):
            self._request_history_refresh()
        self._history_auto_job = self.after(
            self.HISTORY_REFRESH_MS, self._history_auto_refresh
        )

    def _choose_export(self, file_format: str) -> None:
        if self._export_running:
            messagebox.showinfo(PRODUCT_NAME, t("messages.export_in_progress"))
            return
        extension = f".{file_format}"
        path = filedialog.asksaveasfilename(
            parent=self,
            title=f"{file_format.upper()} olarak dışa aktar",
            defaultextension=extension,
            initialfile=f"{PRODUCT_SLUG}_history_{datetime.now():%Y-%m-%d}{extension}",
            filetypes=[
                (f"{file_format.upper()} dosyası", f"*{extension}"),
                ("Tüm dosyalar", "*.*"),
            ],
        )
        if not path:
            return

        range_code = self._history_range_codes.get(
            self.history_range_var.get(), "last_1_hour"
        )
        seconds = HISTORY_RANGES.get(range_code, HISTORY_RANGES["last_1_hour"])
        since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        process_query = self.history_process_var.get()
        event_type = self._connection_event_filter_codes.get(
            self.history_event_type_var.get(), "all"
        )
        protocol = (
            "all"
            if self.history_protocol_var.get() == t("common.all")
            else self.history_protocol_var.get()
        )
        process_event_query = self.process_history_name_var.get()
        process_event_type = self._process_event_filter_codes.get(
            self.process_history_type_var.get(), "all"
        )
        process_event_user = self.process_history_user_var.get()
        process_event_path = self.process_history_path_var.get()
        self._export_running = True
        self.history_status_label.configure(text="Veriler dışa aktarılıyor…")

        def worker() -> None:
            try:
                measurements = self.database.query_measurements(since)
                events = self.database.query_connection_events(since)
                events = filter_connection_events(
                    events,
                    process_query=process_query,
                    event_type=event_type,
                    protocol=protocol,
                )
                process_events = self.database.query_process_events(since)
                process_events = filter_process_events(
                    process_events,
                    process_query=process_event_query,
                    event_type=process_event_type,
                    username_query=process_event_user,
                    path_query=process_event_path,
                )
                network_data = self.network_repository.query_dashboard(limit=100_000)
                network_cutoff = to_db_timestamp(since)
                network_events = [
                    item
                    for item in network_data["events"]
                    if str(item.get("timestamp", "")) >= network_cutoff
                ]
                network_findings = [
                    item
                    for item in network_data["findings"]
                    if str(item.get("timestamp", "")) >= network_cutoff
                ]
                if file_format == "csv":
                    export_history_csv(
                        path,
                        measurements,
                        events,
                        process_events,
                        network_events,
                        network_findings,
                        i18n=self.i18n,
                    )
                else:
                    export_history_json(
                        path,
                        measurements,
                        events,
                        process_events,
                        network_events,
                        network_findings,
                        display_language=self.i18n.language,
                    )
                result = (True, t("messages.export_saved", path=path))
            except Exception as exc:
                result = (False, f"Dışa aktarma başarısız: {exc}")
            self._export_results.put(result)

        self._start_background_worker(worker, "history-exporter")

    def _poll_background_results(self) -> None:
        if self._closing:
            return
        self._poll_history_results()
        self._poll_export_results()
        self._poll_process_detail_results()
        self._poll_network_messages()
        self._poll_detection_results()
        self._poll_detection_actions()
        self._poll_detection_worker()
        self._poll_service_notifications()
        self._background_poll_job = self.after(250, self._poll_background_results)

    def _poll_history_results(self) -> None:
        try:
            generation, measurements, events, process_events, error = (
                self._history_results.get_nowait()
            )
        except queue.Empty:
            return
        self._history_query_running = False
        if generation == self._history_generation:
            if error:
                self.history_status_label.configure(text=error)
            else:
                self._apply_history_data(measurements, events, process_events)
        if self._history_refresh_pending:
            self._history_refresh_pending = False
            self._start_history_query(self._history_generation)

    def _poll_export_results(self) -> None:
        try:
            success, text = self._export_results.get_nowait()
        except queue.Empty:
            return
        self._export_running = False
        self.history_status_label.configure(text=text.replace("\n", " "))
        if success:
            messagebox.showinfo("Dışa aktarma tamamlandı", text)
        else:
            messagebox.showerror("Dışa aktarma hatası", text)

    def _poll_network_messages(self) -> None:
        try:
            text, refresh = self._network_messages.get_nowait()
        except queue.Empty:
            return
        self.status_label.configure(text=text)
        if refresh:
            self._request_connection_refresh(force=True)

    def _poll_detection_results(self) -> None:
        try:
            data, error = self._detection_results.get_nowait()
        except queue.Empty:
            return
        self._detection_query_running = False
        if error:
            self.status_label.configure(text=error)
        elif data is not None:
            self.detection_tab.set_data(data)
            high_new = sum(
                item.get("status") == "new"
                and item.get("severity") in {"high", "critical"}
                for item in data.get("alerts", [])
            )
            self.detection_tab.set_notification_count(high_new)
        if not self._closing:
            self._detection_refresh_job = self.after(
                10_000,
                self._request_detection_refresh,
            )

    def _poll_detection_actions(self) -> None:
        latest: tuple[bool, str, bool] | None = None
        while True:
            try:
                latest = self._detection_actions.get_nowait()
            except queue.Empty:
                break
        if latest is None:
            return
        success, text, refresh = latest
        self.status_label.configure(text=text)
        if not success:
            messagebox.showerror("Tespit sistemi", text, parent=self)
        if refresh:
            self._request_detection_refresh()

    def _poll_detection_worker(self) -> None:
        if self.detection_worker is None:
            return
        refresh = False
        notifications: list[dict[str, Any]] = []
        while True:
            try:
                item = self.detection_worker.notifications.get_nowait()
            except queue.Empty:
                break
            if item.get("kind") == "error":
                self.status_label.configure(text=str(item.get("message", "")))
                continue
            refresh = True
            notifications.extend(
                alert
                for alert in item.get("created_alerts", [])
                if alert.get("notify")
            )
        if notifications and not self.detection_tab.notifications_muted.get():
            latest = notifications[-1]
            self.status_label.configure(
                text=(
                    f"{self.i18n.enum('severity', latest['severity'])}: "
                    f"{latest['rule_id']} — {latest['title']}"
                )
            )
        if refresh:
            self._request_detection_refresh()

    def _poll_service_notifications(self) -> None:
        latest_error: str | None = None
        while True:
            try:
                level, text = self.history_service.notifications.get_nowait()
            except queue.Empty:
                break
            if level == "error":
                latest_error = text
        if latest_error:
            self.status_label.configure(text=latest_error)

    def _start_background_worker(
        self, target: Callable[[], None], name: str
    ) -> None:
        if self._closing:
            return
        self._background_threads = [
            thread for thread in self._background_threads if thread.is_alive()
        ]
        thread = threading.Thread(target=target, name=name, daemon=True)
        self._background_threads.append(thread)
        thread.start()

    def _cancel_job(self, attribute: str) -> None:
        job = getattr(self, attribute)
        if job is None:
            return
        try:
            self.after_cancel(job)
        except tk.TclError:
            pass
        setattr(self, attribute, None)

    def _close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._language_unsubscribe()
        self._shutdown_event.set()
        for attribute in (
            "_metrics_job",
            "_connection_job",
            "_connection_poll_job",
            "_background_poll_job",
            "_history_auto_job",
            "_process_job",
            "_process_poll_job",
            "_detection_refresh_job",
        ):
            self._cancel_job(attribute)
        self.history_service.stop(timeout=3.0)
        if self.detection_worker is not None:
            self.detection_worker.stop(timeout=3.0)
        self.dns_resolver.close()
        for thread in self._background_threads:
            if thread.is_alive():
                thread.join(timeout=0.2)
        self.destroy()
