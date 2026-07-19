"""Passive Network Analysis tab and its read-only subviews."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from tkinter import simpledialog, ttk
from typing import Any

from .i18n import format_datetime, get_i18n, t


class SortableTable(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        columns: dict[str, tuple[str, int, bool]],
        on_details: Callable[[dict[str, Any], str], None],
        kind: str,
    ) -> None:
        super().__init__(parent, style="Card.TFrame", padding=1)
        self.columns = columns
        self.on_details = on_details
        self.kind = kind
        self.records: list[dict[str, Any]] = []
        self.visible: list[dict[str, Any]] = []
        self.by_item: dict[str, dict[str, Any]] = {}
        self.sort_field = next(iter(columns))
        self.descending = False
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            self, columns=tuple(columns), show="headings", selectmode="browse"
        )
        for key, (label, width, _numeric) in columns.items():
            self.tree.heading(key, text=label, command=lambda field=key: self.sort(field))
            self.tree.column(key, width=width, minwidth=65)
        vertical = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<Double-1>", self._details)

    def sort(self, field: str) -> None:
        if self.sort_field == field:
            self.descending = not self.descending
        else:
            self.sort_field, self.descending = field, False
        self.render(self.visible)

    def render(self, records: list[dict[str, Any]]) -> None:
        self.visible = records
        numeric = self.columns[self.sort_field][2]

        def key(record: dict[str, Any]) -> Any:
            value = record.get(self.sort_field, "")
            if numeric:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return -1.0
            return str(value).casefold()

        ordered = sorted(records, key=key, reverse=self.descending)
        selected = self.tree.selection()
        selected_key = (
            self.by_item[selected[0]].get("_stable_key") if selected and selected[0] in self.by_item else None
        )
        y = self.tree.yview()[0] if self.tree.get_children() else 0.0
        existing = list(self.tree.get_children())
        desired: dict[str, dict[str, Any]] = {}
        ids: list[str] = []
        for index, record in enumerate(ordered):
            stable = str(record.get("_stable_key") or record.get("id") or index)
            item_id = f"{self.kind}:{stable}"
            ids.append(item_id)
            desired[item_id] = record
        for item in set(existing) - set(ids):
            self.tree.delete(item)
        for index, item in enumerate(ids):
            values = tuple(
                _display(desired[item].get(column, "—"), column)
                for column in self.columns
            )
            if self.tree.exists(item):
                if tuple(map(str, self.tree.item(item, "values"))) != tuple(map(str, values)):
                    self.tree.item(item, values=values)
                if self.tree.index(item) != index:
                    self.tree.move(item, "", index)
            else:
                self.tree.insert("", index, iid=item, values=values)
        self.by_item = desired
        if selected_key is not None:
            for item, record in desired.items():
                if record.get("_stable_key") == selected_key:
                    self.tree.selection_set(item)
                    break
        if ids:
            self.tree.yview_moveto(y)

    def selected_record(self) -> dict[str, Any] | None:
        selected = self.tree.selection()
        return self.by_item.get(selected[0]) if selected else None

    def _details(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if item in self.by_item:
            self.on_details(self.by_item[item], self.kind)


class NetworkAnalysisTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        on_refresh: Callable[[], None],
        on_details: Callable[[dict[str, Any], str], None],
        on_finding_status: Callable[[int, str], None],
        on_expected: Callable[[str, str | int, bool, str], None],
        on_dns: Callable[[str], None],
    ) -> None:
        super().__init__(parent, style="Root.TFrame", padding=(4, 16, 4, 4))
        self.on_refresh = on_refresh
        self.on_details = on_details
        self.on_finding_status = on_finding_status
        self.on_expected = on_expected
        self.on_dns = on_dns
        self.i18n = get_i18n()
        self.snapshot_connections: list[dict[str, Any]] = []
        self.data: dict[str, Any] = {}
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        top = ttk.Frame(self, style="Root.TFrame")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        top.columnconfigure(0, weight=1)
        ttk.Label(
            top,
            text=t("messages.passive_notice"),
            style="Status.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(
            top, text=t("common.refresh_now"), style="Refresh.TButton", command=on_refresh
        ).grid(row=0, column=1)
        self.views = ttk.Notebook(self)
        self.views.grid(row=1, column=0, sticky="nsew")
        self._build_overview()
        self._build_listeners()
        self._build_endpoints()
        self._build_events()
        self._build_findings()

    def _tab(self, name: str) -> ttk.Frame:
        frame = ttk.Frame(self.views, style="Root.TFrame", padding=12)
        self.views.add(frame, text=name)
        return frame

    def _build_overview(self) -> None:
        parent = self._tab(t("tabs.overview"))
        parent.columnconfigure(0, weight=1)
        cards = ttk.Frame(parent, style="Root.TFrame")
        cards.grid(row=0, column=0, sticky="ew")
        self.summary_vars: dict[str, tk.StringVar] = {}
        labels = (
            ("active", "Aktif bağlantı"), ("tcp", "TCP"), ("udp", "UDP"),
            ("listeners", "Dinleme portu"), ("exposed", "Dışa açık"),
            ("remote_ips", "Benzersiz uzak IP"), ("new_targets", "İlk hedef"),
            ("events24", "24 saat olay"), ("open_findings", "Açık bulgu"),
        )
        for index, (key, label) in enumerate(labels):
            cards.columnconfigure(index, weight=1)
            card = ttk.Frame(cards, style="Card.TFrame", padding=10)
            card.grid(row=0, column=index, sticky="nsew", padx=3)
            ttk.Label(card, text=label, style="CardTitle.TLabel").pack()
            variable = tk.StringVar(value="0")
            self.summary_vars[key] = variable
            ttk.Label(card, textvariable=variable, style="Metric.TLabel").pack()
        lists = ttk.Frame(parent, style="Root.TFrame")
        lists.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        parent.rowconfigure(1, weight=1)
        self.overview_texts: dict[str, tk.Text] = {}
        titles = (
            ("processes", "En fazla bağlantısı olan işlemler"),
            ("ips", "En sık uzak IP adresleri"),
            ("listeners", "Son dinleme portları"),
            ("targets", "Son yeni uzak hedefler"),
            ("findings", "Son ağ bulguları"),
        )
        for index, (key, title) in enumerate(titles):
            lists.columnconfigure(index, weight=1)
            box = ttk.Frame(lists, style="Card.TFrame", padding=8)
            box.grid(row=0, column=index, sticky="nsew", padx=3)
            ttk.Label(box, text=title, style="CardTitle.TLabel").pack(anchor="w")
            text = _text_widget(box, 13)
            text.pack(fill="both", expand=True, pady=(6, 0))
            self.overview_texts[key] = text

    def _build_listeners(self) -> None:
        parent = self._tab(t("tabs.listening_ports"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        filters = ttk.Frame(parent, style="Root.TFrame")
        filters.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filters.columnconfigure(1, weight=1)
        self.listener_search = tk.StringVar()
        ttk.Label(filters, text="IP / port / işlem", style="Filter.TLabel").grid(row=0, column=0)
        entry = ttk.Entry(filters, textvariable=self.listener_search)
        entry.grid(row=0, column=1, sticky="ew", padx=(6, 10))
        entry.bind("<KeyRelease>", self._filter_listeners)
        self.listener_protocol = _combo(filters, (t("common.all"), "TCP", "UDP"), 2, self._filter_listeners)
        self.listener_family = _combo(filters, (t("common.all"), "IPv4", "IPv6"), 3, self._filter_listeners)
        self._scope_codes = {
            t("common.all"): "all",
            **{
                self.i18n.enum("address_scope", code): code
                for code in (
                    "loopback", "private", "link_local",
                    "all_interfaces", "public",
                )
            },
        }
        self.listener_scope = _combo(
            filters,
            tuple(self._scope_codes),
            4,
            self._filter_listeners,
        )
        self.listener_new = tk.BooleanVar()
        self.listener_exposed = tk.BooleanVar()
        ttk.Checkbutton(filters, text="Yalnızca yeni", variable=self.listener_new, command=self._filter_listeners).grid(row=0, column=5, padx=6)
        ttk.Checkbutton(filters, text="Yalnızca dışa açık", variable=self.listener_exposed, command=self._filter_listeners).grid(row=0, column=6, padx=6)
        ttk.Button(filters, text="Temizle", style="Secondary.TButton", command=self._clear_listener_filters).grid(row=0, column=7)
        columns = {
            "protocol": ("Protokol", 75, False), "address_family": ("IP Ailesi", 80, False),
            "local_ip": ("Yerel IP", 145, False), "local_port": ("Port", 80, True),
            "address_scope_display": (t("columns.scope"), 120, False), "process_name": (t("common.process"), 155, False),
            "pid": ("PID", 70, True), "username": ("Kullanıcı", 140, False),
            "first_seen": ("İlk Görülme", 150, False), "last_seen": ("Son Görülme", 150, False),
            "duration": ("Süre", 90, True), "status": ("Durum", 90, False),
        }
        self.listener_table = SortableTable(parent, columns, self.on_details, "listener")
        self.listener_table.grid(row=1, column=0, sticky="nsew")
        actions = ttk.Frame(parent, style="Root.TFrame")
        actions.grid(row=2, column=0, sticky="e", pady=(7, 0))
        ttk.Button(actions, text="Beklenen Olarak İşaretle", style="Secondary.TButton", command=lambda: self._mark_expected("listener", True)).pack(side="left", padx=4)
        ttk.Button(actions, text="Beklenen İşaretini Kaldır", style="Secondary.TButton", command=lambda: self._mark_expected("listener", False)).pack(side="left")

    def _build_endpoints(self) -> None:
        parent = self._tab(t("tabs.remote_endpoints"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        filters = ttk.Frame(parent, style="Root.TFrame")
        filters.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filters.columnconfigure(1, weight=1)
        self.endpoint_search = tk.StringVar()
        ttk.Label(filters, text="IP / port / işlem", style="Filter.TLabel").grid(row=0, column=0)
        entry = ttk.Entry(filters, textvariable=self.endpoint_search)
        entry.grid(row=0, column=1, sticky="ew", padx=(6, 10))
        entry.bind("<KeyRelease>", self._filter_endpoints)
        self.endpoint_protocol = _combo(filters, (t("common.all"), "TCP", "UDP"), 2, self._filter_endpoints)
        self.endpoint_family = _combo(filters, (t("common.all"), "IPv4", "IPv6"), 3, self._filter_endpoints)
        self.endpoint_scope = _combo(filters, tuple(self._scope_codes), 4, self._filter_endpoints)
        self.endpoint_time = _combo(filters, ("Tüm zamanlar", "Son 15 dakika", "Son 1 saat", "Son 24 saat", "Son 7 gün"), 5, self._filter_endpoints, default="Son 24 saat")
        self.endpoint_new = tk.BooleanVar()
        ttk.Checkbutton(filters, text="Yalnızca ilk görülen", variable=self.endpoint_new, command=self._filter_endpoints).grid(row=0, column=6, padx=6)
        columns = {
            "remote_ip": ("Uzak IP", 150, False), "remote_port": ("Port", 80, True),
            "hostname": ("Ana Bilgisayar", 180, False),
            "protocol": ("Protokol", 75, False), "address_family": ("IP Ailesi", 80, False),
            "address_scope_display": (t("columns.scope"), 120, False), "first_seen": (t("columns.first_seen"), 150, False),
            "last_seen": ("Son Görülme", 150, False), "seen_count": ("Görülme", 80, True),
            "process_count": ("İşlem Sayısı", 90, True), "last_process_name": ("Son İşlem", 150, False),
            "last_event_type_display": (t("columns.status"), 130, False),
        }
        self.endpoint_table = SortableTable(parent, columns, self.on_details, "endpoint")
        self.endpoint_table.grid(row=1, column=0, sticky="nsew")
        actions = ttk.Frame(parent, style="Root.TFrame")
        actions.grid(row=2, column=0, sticky="e", pady=(7, 0))
        ttk.Button(actions, text="Ters DNS Çöz", style="Secondary.TButton", command=self._resolve_selected).pack(side="left", padx=4)
        ttk.Button(actions, text="Beklenen Olarak İşaretle", style="Secondary.TButton", command=lambda: self._mark_expected("endpoint", True)).pack(side="left", padx=4)
        ttk.Button(actions, text="Beklenen İşaretini Kaldır", style="Secondary.TButton", command=lambda: self._mark_expected("endpoint", False)).pack(side="left")

    def _build_events(self) -> None:
        parent = self._tab(t("tabs.network_events"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        filters = ttk.Frame(parent, style="Root.TFrame")
        filters.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filters.columnconfigure(1, weight=1)
        self.event_search = tk.StringVar()
        ttk.Label(filters, text="İşlem / PID / IP / port", style="Filter.TLabel").grid(row=0, column=0)
        entry = ttk.Entry(filters, textvariable=self.event_search)
        entry.grid(row=0, column=1, sticky="ew", padx=(6, 10))
        entry.bind("<KeyRelease>", self._filter_events)
        self._event_codes = {
            t("common.all"): "all",
            **{
                self.i18n.enum("event_type", code): code
                for code in (
                    "connection_opened", "connection_closed",
                    "listener_started", "listener_stopped",
                    "remote_endpoint_new", "remote_endpoint_reappeared",
                )
            },
        }
        self.event_type = _combo(
            filters,
            tuple(self._event_codes),
            2,
            self._filter_events,
        )
        self.event_protocol = _combo(filters, (t("common.all"), "TCP", "UDP"), 3, self._filter_events)
        self.event_time = _combo(
            filters,
            ("Tüm zamanlar", "Son 15 dakika", "Son 1 saat", "Son 24 saat", "Son 7 gün"),
            4,
            self._filter_events,
            default="Son 24 saat",
        )
        self.event_public = tk.BooleanVar()
        self.event_listening = tk.BooleanVar()
        ttk.Checkbutton(filters, text="Yalnızca public", variable=self.event_public, command=self._filter_events).grid(row=0, column=5, padx=6)
        ttk.Checkbutton(filters, text="Yalnızca dinleme", variable=self.event_listening, command=self._filter_events).grid(row=0, column=6, padx=6)
        columns = {
            "timestamp": (t("columns.timestamp"), 150, False), "event_type_display": (t("columns.event_type"), 180, False),
            "protocol": ("Protokol", 75, False), "process_name": ("İşlem", 150, False),
            "pid": ("PID", 70, True), "local_address": ("Yerel Adres", 180, False),
            "remote_address": ("Uzak Adres", 180, False), "description": ("Açıklama", 340, False),
        }
        self.event_table = SortableTable(parent, columns, self.on_details, "event")
        self.event_table.grid(row=1, column=0, sticky="nsew")

    def _build_findings(self) -> None:
        parent = self._tab(t("tabs.findings"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        filters = ttk.Frame(parent, style="Root.TFrame")
        filters.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filters.columnconfigure(1, weight=1)
        self.finding_search = tk.StringVar()
        ttk.Label(filters, text="İşlem / IP / kural", style="Filter.TLabel").grid(row=0, column=0)
        entry = ttk.Entry(filters, textvariable=self.finding_search)
        entry.grid(row=0, column=1, sticky="ew", padx=(6, 10))
        entry.bind("<KeyRelease>", self._filter_findings)
        self._severity_codes = {
            t("common.all"): "all",
            **{self.i18n.enum("severity", code): code for code in ("info", "low", "medium", "high")},
        }
        self._finding_status_codes = {
            t("common.all"): "all",
            **{self.i18n.enum("finding_status", code): code for code in ("open", "reviewed", "ignored")},
        }
        self.finding_severity = _combo(filters, tuple(self._severity_codes), 2, self._filter_findings)
        self.finding_status = _combo(filters, tuple(self._finding_status_codes), 3, self._filter_findings)
        self.finding_time = _combo(
            filters,
            ("Tüm zamanlar", "Son 15 dakika", "Son 1 saat", "Son 24 saat", "Son 7 gün"),
            4,
            self._filter_findings,
            default="Tüm zamanlar",
        )
        columns = {
            "timestamp": (t("columns.timestamp"), 150, False), "severity_display": (t("columns.severity"), 80, False),
            "rule_id": ("Kural", 80, False), "title": ("Başlık", 250, False),
            "process_name": ("İşlem", 150, False), "local_address": ("Yerel Adres", 170, False),
            "remote_address": (t("common.remote_address"), 170, False), "status_display": (t("columns.status"), 90, False),
        }
        self.finding_table = SortableTable(parent, columns, self.on_details, "finding")
        self.finding_table.grid(row=1, column=0, sticky="nsew")
        ttk.Label(
            parent,
            text=t("messages.finding_disclaimer"),
            style="Status.TLabel",
        ).grid(row=2, column=0, sticky="w", pady=(7, 0))
        actions = ttk.Frame(parent, style="Root.TFrame")
        actions.grid(row=2, column=0, sticky="e", pady=(7, 0))
        for text, status in (
            (self.i18n.enum("finding_status", "reviewed"), "reviewed"),
            (self.i18n.enum("finding_status", "ignored"), "ignored"),
            (t("common.refresh"), "open"),
        ):
            ttk.Button(actions, text=text, style="Secondary.TButton", command=lambda value=status: self._set_finding(value)).pack(side="left", padx=3)

    def set_data(
        self, snapshot_connections: list[dict[str, Any]], data: dict[str, Any]
    ) -> None:
        self.snapshot_connections = snapshot_connections
        self.data = data
        listeners = data.get("listeners", [])
        endpoints = data.get("endpoints", [])
        events = data.get("events", [])
        findings = data.get("findings", [])
        now = datetime.now(timezone.utc)
        for item in listeners:
            item["_stable_key"] = item["identity_key"]
            item["status"] = self.i18n.enum("network_status", "listening")
            item["address_scope_display"] = self.i18n.enum(
                "address_scope", item.get("address_scope")
            )
            item["duration"] = _duration_seconds(item["first_seen"], now)
        for item in endpoints:
            item["_stable_key"] = item["id"]
            item["address_scope_display"] = self.i18n.enum(
                "address_scope", item.get("address_scope")
            )
            item["last_event_type_display"] = self.i18n.enum(
                "event_type", item.get("last_event_type")
            ) if item.get("last_event_type") not in {"baseline", "seen"} else str(
                item.get("last_event_type", "")
            ).title()
        for item in events:
            item["_stable_key"] = item["id"]
            item["event_type_display"] = self.i18n.enum(
                "event_type", item.get("event_type")
            )
            item["local_address"] = f"{item['local_ip']}:{item['local_port']}"
            item["remote_address"] = f"{item['remote_ip']}:{item['remote_port']}"
        for item in findings:
            item["_stable_key"] = item["id"]
            item["severity_display"] = self.i18n.enum(
                "severity", item.get("severity")
            )
            item["status_display"] = self.i18n.enum(
                "finding_status", item.get("status")
            )
            item["title"] = self.i18n.optional(
                f"network_rules.{item.get('rule_id')}.title",
                str(item.get("title", "")),
            )
            item["description"] = self.i18n.optional(
                f"network_rules.{item.get('rule_id')}.description",
                str(item.get("description", "")),
            )
        self.listener_table.records = listeners
        self.endpoint_table.records = endpoints
        self.event_table.records = events
        self.finding_table.records = findings
        self._filter_listeners()
        self._filter_endpoints()
        self._filter_events()
        self._filter_findings()
        self._update_overview()

    def _update_overview(self) -> None:
        connections = self.snapshot_connections
        listeners = self.data.get("listeners", [])
        endpoints = self.data.get("endpoints", [])
        findings = self.data.get("findings", [])
        values = {
            "active": len(connections),
            "tcp": sum(item["protocol"] == "TCP" for item in connections),
            "udp": sum(item["protocol"] == "UDP" for item in connections),
            "listeners": len(listeners),
            "exposed": sum(bool(item.get("is_active")) and item["address_scope"] != "loopback" for item in listeners),
            "remote_ips": len({item["remote_ip"] for item in endpoints}),
            "new_targets": sum(item.get("last_event_type") == "remote_endpoint_new" for item in endpoints),
            "events24": self.data.get("event_count_24h", 0),
            "open_findings": sum(item["status"] == "open" for item in findings),
        }
        for key, value in values.items():
            self.summary_vars[key].set(str(value))
        process_counts: dict[str, int] = {}
        ip_counts: dict[str, int] = {}
        for item in connections:
            process_counts[item.get("process_name", "Bilinmiyor")] = process_counts.get(item.get("process_name", "Bilinmiyor"), 0) + 1
            ip = item.get("remote_ip", "—")
            if ip != "—":
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        _set_text(self.overview_texts["processes"], _ranked(process_counts))
        _set_text(self.overview_texts["ips"], _ranked(ip_counts))
        _set_text(self.overview_texts["listeners"], "\n".join(f"{x['process_name']} — {x['local_ip']}:{x['local_port']}" for x in listeners[:8]) or "Veri yok.")
        _set_text(self.overview_texts["targets"], "\n".join(f"{x['last_process_name']} — {x['remote_ip']}:{x['remote_port']}" for x in endpoints[:8]) or "Veri yok.")
        _set_text(self.overview_texts["findings"], "\n".join(f"[{x['severity_display']}] {x['title']}" for x in findings[:8]) or t("common.no_data"))

    def _filter_listeners(self, _event: tk.Event | None = None) -> None:
        needle = self.listener_search.get().casefold()
        records = [
            item for item in self.listener_table.records
            if (not needle or needle in f"{item['local_ip']} {item['local_port']} {item['process_name']}".casefold())
            and (self.listener_protocol.get() == t("common.all") or item["protocol"] == self.listener_protocol.get())
            and (self.listener_family.get() == t("common.all") or item["address_family"] == self.listener_family.get())
            and (self._scope_codes.get(self.listener_scope.get(), "all") == "all" or item["address_scope"] == self._scope_codes.get(self.listener_scope.get()))
            and (not self.listener_new.get() or item["seen_count"] <= 2)
            and (not self.listener_exposed.get() or item["address_scope"] != "loopback")
        ]
        self.listener_table.render(records)

    def _filter_endpoints(self, _event: tk.Event | None = None) -> None:
        needle = self.endpoint_search.get().casefold()
        cutoff = _time_cutoff(self.endpoint_time.get())
        records = [
            item for item in self.endpoint_table.records
            if (not needle or needle in f"{item['remote_ip']} {item['remote_port']} {item.get('process_names','')}".casefold())
            and (self.endpoint_protocol.get() == t("common.all") or item["protocol"] == self.endpoint_protocol.get())
            and (self.endpoint_family.get() == t("common.all") or item["address_family"] == self.endpoint_family.get())
            and (self._scope_codes.get(self.endpoint_scope.get(), "all") == "all" or item["address_scope"] == self._scope_codes.get(self.endpoint_scope.get()))
            and (not self.endpoint_new.get() or bool(item["is_first_seen"]))
            and (cutoff is None or _parse_time(item["last_seen"]) >= cutoff)
        ]
        self.endpoint_table.render(records)

    def _filter_events(self, _event: tk.Event | None = None) -> None:
        needle = self.event_search.get().casefold()
        cutoff = _time_cutoff(self.event_time.get())
        records = [
            item for item in self.event_table.records
            if (not needle or needle in f"{item['process_name']} {item['pid']} {item['local_ip']} {item['local_port']} {item['remote_ip']} {item['remote_port']}".casefold())
            and (self._event_codes.get(self.event_type.get(), "all") == "all" or item["event_type"] == self._event_codes.get(self.event_type.get()))
            and (self.event_protocol.get() == t("common.all") or item["protocol"] == self.event_protocol.get())
            and (not self.event_public.get() or item["address_scope"] == "public")
            and (not self.event_listening.get() or item["event_type"] in {"listener_started", "listener_stopped"})
            and (cutoff is None or _parse_time(item["timestamp"]) >= cutoff)
        ]
        self.event_table.render(records)

    def _filter_findings(self, _event: tk.Event | None = None) -> None:
        needle = self.finding_search.get().casefold()
        cutoff = _time_cutoff(self.finding_time.get())
        records = [
            item for item in self.finding_table.records
            if (not needle or needle in f"{item['process_name']} {item['local_address']} {item['remote_address']} {item['rule_id']}".casefold())
            and (self._severity_codes.get(self.finding_severity.get(), "all") == "all" or item["severity"] == self._severity_codes.get(self.finding_severity.get()))
            and (self._finding_status_codes.get(self.finding_status.get(), "all") == "all" or item["status"] == self._finding_status_codes.get(self.finding_status.get()))
            and (cutoff is None or _parse_time(item["timestamp"]) >= cutoff)
        ]
        self.finding_table.render(records)

    def _clear_listener_filters(self) -> None:
        self.listener_search.set("")
        for combo in (self.listener_protocol, self.listener_family, self.listener_scope):
            combo.set(t("common.all"))
        self.listener_new.set(False)
        self.listener_exposed.set(False)
        self._filter_listeners()

    def _set_finding(self, status: str) -> None:
        record = self.finding_table.selected_record()
        if record:
            self.on_finding_status(int(record["id"]), status)

    def _mark_expected(self, kind: str, expected: bool) -> None:
        table = self.listener_table if kind == "listener" else self.endpoint_table
        record = table.selected_record()
        if not record:
            return
        note = simpledialog.askstring("Kullanıcı notu", "Bu baseline kaydı için not:", parent=self) or ""
        key = record["identity_key"] if kind == "listener" else record["id"]
        self.on_expected(kind, key, expected, note)

    def _resolve_selected(self) -> None:
        record = self.endpoint_table.selected_record()
        if record:
            self.on_dns(str(record["remote_ip"]))


def _combo(parent: ttk.Frame, values: tuple[str, ...], column: int, callback: Callable, default: str | None = None) -> ttk.Combobox:
    combo = ttk.Combobox(parent, values=values, state="readonly", width=14)
    combo.set(default if default in values else values[0])
    combo.grid(row=0, column=column, padx=4)
    combo.bind("<<ComboboxSelected>>", callback)
    return combo


def _display(value: Any, field: str = "") -> str:
    if (
        value not in {None, "", "—"}
        and (
            field in {"timestamp", "first_seen", "last_seen", "created_at", "updated_at"}
            or field.endswith("_at")
        )
    ):
        return format_datetime(str(value))
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value if value not in {None, ""} else "—")


def _text_widget(parent: tk.Misc, height: int) -> tk.Text:
    return tk.Text(parent, height=height, wrap="word", background="#1e293b", foreground="#cbd5e1", relief="flat", font=("Segoe UI", 9))


def _set_text(widget: tk.Text, value: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value)
    widget.configure(state="disabled")


def _ranked(values: dict[str, int]) -> str:
    return "\n".join(f"{name}: {count}" for name, count in sorted(values.items(), key=lambda item: item[1], reverse=True)[:8]) or "Veri yok."


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _time_cutoff(label: str) -> datetime | None:
    seconds = {
        "Son 15 dakika": 900, "Last 15 Minutes": 900,
        "Son 1 saat": 3600, "Last 1 Hour": 3600,
        "Son 24 saat": 86400, "Last 24 Hours": 86400,
        "Son 7 gün": 604800, "Last 7 Days": 604800,
    }.get(label)
    return datetime.now(timezone.utc) - timedelta(seconds=seconds) if seconds else None


def _duration_seconds(value: str, now: datetime) -> int:
    return max(0, int((now - _parse_time(value)).total_seconds()))
