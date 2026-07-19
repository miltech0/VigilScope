"""Process list, filters, sorting, and parent-child tree interface."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from datetime import datetime
from tkinter import ttk
from typing import Any

from .process_filters import filter_processes, sort_processes
from .process_models import ProcessRecord, identity_text, process_identity
from .process_tree import ProcessTreeNode, build_process_forest
from .i18n import format_datetime, get_i18n, t


class ProcessTab(ttk.Frame):
    COLUMN_SPECS = {
        "name": ("columns.process_name", 170),
        "pid": ("columns.pid", 75),
        "ppid": ("columns.parent_pid", 90),
        "parent_name": ("columns.parent_process_name", 150),
        "username": ("columns.username", 155),
        "status": ("columns.status", 105),
        "cpu_percent": ("columns.cpu_percent", 75),
        "ram_mb": ("columns.ram_mb", 90),
        "ram_percent": ("columns.ram_percent", 75),
        "num_threads": ("columns.threads", 100),
        "start_time": ("columns.start_time", 145),
        "exe": ("columns.executable", 280),
        "network_count": ("columns.network_connections", 105),
    }

    def __init__(
        self,
        parent: tk.Misc,
        on_refresh: Callable[[], None],
        on_open_details: Callable[[ProcessRecord], None],
    ) -> None:
        super().__init__(parent, style="Root.TFrame", padding=(4, 16, 4, 4))
        self.on_refresh = on_refresh
        self.i18n = get_i18n()
        self._column_specs = {
            column: (t(key), width)
            for column, (key, width) in self.COLUMN_SPECS.items()
        }
        self.on_open_details = on_open_details
        self._all_records: list[ProcessRecord] = []
        self._visible_records: list[ProcessRecord] = []
        self._records_by_item: dict[str, ProcessRecord] = {}
        self._tree_records_by_item: dict[str, ProcessRecord] = {}
        self._sort_field = "name"
        self._sort_descending = False
        self._tree_has_rendered = False

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self._build_controls()
        self._build_views()

    def _build_controls(self) -> None:
        filters = ttk.Frame(self, style="Root.TFrame")
        filters.grid(row=0, column=0, sticky="ew")
        filters.columnconfigure(1, weight=1)
        filters.columnconfigure(7, weight=1)

        ttk.Label(filters, text=t("common.search"), style="Filter.TLabel").grid(
            row=0, column=0, padx=(0, 7)
        )
        self.search_var = tk.StringVar()
        search = ttk.Entry(filters, textvariable=self.search_var)
        search.grid(row=0, column=1, sticky="ew", padx=(0, 14))
        search.bind("<KeyRelease>", self._apply_filters)

        ttk.Label(filters, text=t("common.status"), style="Filter.TLabel").grid(
            row=0, column=2, padx=(0, 7)
        )
        self.status_var = tk.StringVar(value=t("common.all"))
        self.status_combo = ttk.Combobox(
            filters,
            textvariable=self.status_var,
            values=(t("common.all"),),
            state="readonly",
            width=15,
        )
        self.status_combo.grid(row=0, column=3, padx=(0, 14))
        self.status_combo.bind("<<ComboboxSelected>>", self._apply_filters)

        self.network_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            filters,
            text="Yalnızca ağı olanlar",
            variable=self.network_only_var,
            command=self._apply_filters,
        ).grid(row=0, column=4, padx=(0, 14))

        ttk.Label(filters, text="Min. CPU %", style="Filter.TLabel").grid(
            row=0, column=5, padx=(0, 7)
        )
        self.minimum_cpu_var = tk.StringVar()
        minimum_cpu = ttk.Entry(filters, textvariable=self.minimum_cpu_var, width=8)
        minimum_cpu.grid(row=0, column=6, padx=(0, 14))
        minimum_cpu.bind("<KeyRelease>", self._apply_filters)

        ttk.Label(filters, text="Min. RAM MB", style="Filter.TLabel").grid(
            row=0, column=7, sticky="e", padx=(0, 7)
        )
        self.minimum_ram_var = tk.StringVar()
        minimum_ram = ttk.Entry(filters, textvariable=self.minimum_ram_var, width=9)
        minimum_ram.grid(row=0, column=8, padx=(0, 12))
        minimum_ram.bind("<KeyRelease>", self._apply_filters)

        ttk.Button(
            filters,
            text=t("common.clear_filters"),
            style="Secondary.TButton",
            command=self.clear_filters,
        ).grid(row=0, column=9, padx=(0, 8))
        ttk.Button(
            filters,
            text=t("common.refresh"),
            style="Refresh.TButton",
            command=self.on_refresh,
        ).grid(row=0, column=10)

        self.count_label = ttk.Label(
            self, text=t("common.scanning"), style="Status.TLabel"
        )
        self.count_label.grid(row=1, column=0, sticky="w", pady=(9, 6))

    def _build_views(self) -> None:
        self.views = ttk.Notebook(self)
        self.views.grid(row=2, column=0, sticky="nsew")
        list_view = ttk.Frame(self.views, style="Card.TFrame", padding=1)
        tree_view = ttk.Frame(self.views, style="Card.TFrame", padding=1)
        self.views.add(list_view, text=t("tabs.process_list"))
        self.views.add(tree_view, text=t("tabs.process_tree"))

        for view in (list_view, tree_view):
            view.columnconfigure(0, weight=1)
            view.rowconfigure(0, weight=1)

        columns = tuple(self._column_specs)
        self.table = ttk.Treeview(
            list_view, columns=columns, show="headings", selectmode="browse"
        )
        for column, (heading, width) in self._column_specs.items():
            self.table.heading(
                column,
                text=heading,
                command=lambda selected=column: self.sort_by(selected),
            )
            self.table.column(
                column,
                width=width,
                minwidth=65,
                anchor=(
                    "center"
                    if column
                    in {
                        "pid",
                        "ppid",
                        "status",
                        "cpu_percent",
                        "ram_mb",
                        "ram_percent",
                        "num_threads",
                        "network_count",
                    }
                    else "w"
                ),
            )
        _attach_scrollbars(list_view, self.table)
        self.table.bind("<Double-1>", self._open_list_details)

        self.tree = ttk.Treeview(
            tree_view,
            columns=("cpu", "ram"),
            show="tree headings",
            selectmode="browse",
        )
        self.tree.heading("#0", text="İşlem / PID")
        self.tree.heading("cpu", text="CPU %")
        self.tree.heading("ram", text="RAM MB")
        self.tree.column("#0", width=460, minwidth=220)
        self.tree.column("cpu", width=90, anchor="center")
        self.tree.column("ram", width=100, anchor="center")
        _attach_scrollbars(tree_view, self.tree)
        self.tree.bind("<Double-1>", self._open_tree_details)
        self._update_heading_labels()

    def set_processes(self, records: list[ProcessRecord]) -> None:
        self._all_records = records
        statuses = sorted(
            {str(record["status"]) for record in records},
            key=str.casefold,
        )
        self._status_codes = {
            t("common.all"): "all",
            **{
                self.i18n.enum("process_status", status): status
                for status in statuses
            },
        }
        self.status_combo.configure(values=tuple(self._status_codes))
        if self.status_var.get() not in self._status_codes:
            self.status_var.set(t("common.all"))
        self._apply_filters()

    def clear_filters(self) -> None:
        self.search_var.set("")
        self.status_var.set(t("common.all"))
        self.network_only_var.set(False)
        self.minimum_cpu_var.set("")
        self.minimum_ram_var.set("")
        self._apply_filters()

    def sort_by(self, field: str) -> None:
        if self._sort_field == field:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_field = field
            self._sort_descending = False
        self._update_heading_labels()
        self._apply_filters()

    def _update_heading_labels(self) -> None:
        for column, (label, _width) in self._column_specs.items():
            suffix = ""
            if column == self._sort_field:
                suffix = " ▼" if self._sort_descending else " ▲"
            self.table.heading(
                column,
                text=label + suffix,
                command=lambda selected=column: self.sort_by(selected),
            )

    def _apply_filters(self, _event: tk.Event | None = None) -> None:
        result = filter_processes(
            self._all_records,
            query=self.search_var.get(),
            status=getattr(self, "_status_codes", {}).get(
                self.status_var.get(), "all"
            ),
            network_only=self.network_only_var.get(),
            minimum_cpu=self.minimum_cpu_var.get(),
            minimum_ram_mb=self.minimum_ram_var.get(),
        )
        self._visible_records = sort_processes(
            result.records, self._sort_field, self._sort_descending
        )
        status = (
            f"{len(self._visible_records)} gösteriliyor / "
            f"{len(self._all_records)} toplam işlem"
        )
        if result.invalid_fields:
            status += f" • Geçersiz {', '.join(result.invalid_fields)} filtresi yok sayıldı"
        self.count_label.configure(text=status)
        self._update_table()
        self._update_tree()

    def _update_table(self) -> None:
        selected = self.table.selection()
        selected_id = selected[0] if selected else None
        y_position = self.table.yview()[0] if self.table.get_children() else 0.0
        desired_ids: list[str] = []
        desired_records: dict[str, ProcessRecord] = {}
        for record in self._visible_records:
            item_id = identity_text(process_identity(record))
            desired_ids.append(item_id)
            desired_records[item_id] = record

        existing = set(self.table.get_children())
        desired = set(desired_ids)
        for item_id in existing - desired:
            self.table.delete(item_id)
        for index, item_id in enumerate(desired_ids):
            values = self._table_values(desired_records[item_id])
            if item_id in existing:
                current = tuple(
                    str(value) for value in self.table.item(item_id, "values")
                )
                desired_values = tuple(str(value) for value in values)
                if current != desired_values:
                    self.table.item(item_id, values=values)
                if self.table.index(item_id) != index:
                    self.table.move(item_id, "", index)
            else:
                self.table.insert("", index, iid=item_id, values=values)

        self._records_by_item = desired_records
        if selected_id in desired:
            self.table.selection_set(selected_id)
            self.table.focus(selected_id)
        if desired_ids:
            self.table.yview_moveto(y_position)

    def _update_tree(self) -> None:
        open_items = {
            item_id
            for item_id in self._walk_tree_items()
            if self.tree.item(item_id, "open")
        }
        selected = self.tree.selection()
        selected_id = selected[0] if selected else None
        self.tree.delete(*self.tree.get_children())
        self._tree_records_by_item.clear()

        forest = build_process_forest(self._visible_records)
        for node in forest.roots:
            self._insert_tree_node("", node, open_items)
        if forest.orphans:
            orphan_id = "process-orphans"
            self.tree.insert(
                "",
                "end",
                iid=orphan_id,
                text=t("process.orphan_root"),
                values=("", ""),
                open=orphan_id in open_items or not self._tree_has_rendered,
            )
            for node in forest.orphans:
                self._insert_tree_node(orphan_id, node, open_items)
        if selected_id and self.tree.exists(selected_id):
            self.tree.selection_set(selected_id)
            self.tree.focus(selected_id)
        self._tree_has_rendered = True

    def _insert_tree_node(
        self, parent: str, node: ProcessTreeNode, open_items: set[str]
    ) -> None:
        item_id = identity_text(process_identity(node.record))
        self.tree.insert(
            parent,
            "end",
            iid=item_id,
            text=f"{node.record['name']} (PID {node.record['pid']})",
            values=(
                f"{float(node.record['cpu_percent']):.1f}",
                f"{float(node.record['ram_mb']):.1f}",
            ),
            open=item_id in open_items,
        )
        self._tree_records_by_item[item_id] = node.record
        for child in node.children:
            self._insert_tree_node(item_id, child, open_items)

    def _walk_tree_items(self) -> list[str]:
        result: list[str] = []
        pending = list(self.tree.get_children())
        while pending:
            item_id = pending.pop()
            result.append(item_id)
            pending.extend(self.tree.get_children(item_id))
        return result

    def _table_values(self, record: ProcessRecord) -> tuple[Any, ...]:
        return (
            record["name"],
            record["pid"],
            record["ppid"],
            record["parent_name"],
            record["username"],
            self.i18n.enum("process_status", record["status"]),
            f"{float(record['cpu_percent']):.1f}",
            f"{float(record['ram_mb']):.1f}",
            f"{float(record['ram_percent']):.1f}",
            record["num_threads"],
            (
                format_datetime(
                    datetime.fromtimestamp(float(record["create_time"])),
                    self.i18n.language,
                )
                if isinstance(record.get("create_time"), (int, float))
                else t("common.unknown")
            ),
            record["exe"],
            record["network_count"],
        )

    def _open_list_details(self, event: tk.Event) -> None:
        item_id = self.table.identify_row(event.y)
        record = self._records_by_item.get(item_id)
        if record:
            self.on_open_details(record)

    def _open_tree_details(self, event: tk.Event) -> None:
        item_id = self.tree.identify_row(event.y)
        record = self._tree_records_by_item.get(item_id)
        if record:
            self.on_open_details(record)


def _attach_scrollbars(parent: ttk.Frame, tree: ttk.Treeview) -> None:
    vertical = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
