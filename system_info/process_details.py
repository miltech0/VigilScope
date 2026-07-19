"""Read-only process details window."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import ttk
from typing import Any

from .process_models import ProcessRecord
from .i18n import get_i18n, localize_widget_tree, t


class ProcessDetailWindow(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        record: ProcessRecord,
        on_refresh: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.record = dict(record)
        self.i18n = get_i18n()
        self.on_refresh = on_refresh
        self.title(
            t(
                "process_details.window_title",
                name=record["name"],
                pid=record["pid"],
            )
        )
        self.geometry("940x760")
        self.minsize(760, 620)
        self.configure(bg="#0f172a")
        self.transient(parent)
        self._variables: dict[str, tk.StringVar] = {}
        self._build()
        localize_widget_tree(self, self.i18n)
        self.update_details(record)

    def _build(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=18)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        actions = ttk.Frame(root, style="Root.TFrame")
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        actions.columnconfigure(0, weight=1)
        self.loading_label = ttk.Label(
            actions, text="Ayrıntılar yükleniyor…", style="Status.TLabel"
        )
        self.loading_label.grid(row=0, column=0, sticky="w")
        ttk.Button(
            actions, text="PID Kopyala", style="Secondary.TButton",
            command=lambda: self._copy(str(self.record.get("pid", ""))),
        ).grid(row=0, column=1, padx=(6, 0))
        ttk.Button(
            actions, text="Dosya Yolunu Kopyala", style="Secondary.TButton",
            command=lambda: self._copy(str(self.record.get("exe", ""))),
        ).grid(row=0, column=2, padx=(6, 0))
        ttk.Button(
            actions, text="Komut Satırını Kopyala", style="Secondary.TButton",
            command=lambda: self._copy(str(self.record.get("command_line", ""))),
        ).grid(row=0, column=3, padx=(6, 0))
        ttk.Button(
            actions, text=t("common.refresh"), style="Refresh.TButton", command=self._refresh
        ).grid(row=0, column=4, padx=(6, 0))

        notebook = ttk.Notebook(root)
        notebook.grid(row=1, column=0, sticky="nsew")
        general = ttk.Frame(notebook, style="Root.TFrame", padding=14)
        network = ttk.Frame(notebook, style="Root.TFrame", padding=14)
        relations = ttk.Frame(notebook, style="Root.TFrame", padding=14)
        notebook.add(general, text=t("tabs.overview"))
        notebook.add(network, text=t("tabs.active_connections"))
        notebook.add(relations, text=t("process_details.relationships"))
        self._build_general(general)
        self._build_network(network)
        self._build_relations(relations)

    def _build_general(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        fields = (
            ("name", t("columns.process_name")),
            ("pid", t("columns.pid")),
            ("ppid", t("columns.parent_pid")),
            ("parent_name", t("columns.parent_process_name")),
            ("status", t("columns.status")),
            ("username", t("columns.username")),
            ("start_time", t("columns.start_time")),
            ("uptime", t("process_details.uptime")),
            ("cpu_percent", t("columns.cpu_percent")),
            ("ram_mb", t("columns.ram_mb")),
            ("num_threads", t("columns.threads")),
            ("open_files_count", t("process_details.open_files")),
        )
        for row, (key, label) in enumerate(fields):
            ttk.Label(parent, text=label, style="Filter.TLabel").grid(
                row=row, column=0, sticky="nw", padx=(0, 18), pady=4
            )
            variable = tk.StringVar(value="—")
            self._variables[key] = variable
            ttk.Label(parent, textvariable=variable, style="Subtitle.TLabel").grid(
                row=row, column=1, sticky="nw", pady=4
            )

        row = len(fields)
        ttk.Label(parent, text="Dosya yolu", style="Filter.TLabel").grid(
            row=row, column=0, sticky="nw", padx=(0, 18), pady=(8, 4)
        )
        self.exe_text = _readonly_text(parent, height=2)
        self.exe_text.grid(row=row, column=1, sticky="ew", pady=(8, 4))
        ttk.Label(parent, text="Çalışma dizini", style="Filter.TLabel").grid(
            row=row + 1, column=0, sticky="nw", padx=(0, 18), pady=4
        )
        self.cwd_text = _readonly_text(parent, height=2)
        self.cwd_text.grid(row=row + 1, column=1, sticky="ew", pady=4)
        ttk.Label(parent, text="Komut satırı", style="Filter.TLabel").grid(
            row=row + 2, column=0, sticky="nw", padx=(0, 18), pady=4
        )
        self.command_text = _readonly_text(parent, height=4)
        self.command_text.grid(row=row + 2, column=1, sticky="ew", pady=4)

    def _build_network(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        columns = (
            "protocol", "local_ip", "local_port", "remote_ip", "remote_port", "status"
        )
        self.network_tree = ttk.Treeview(parent, columns=columns, show="headings")
        labels = {
            "protocol": "Protokol", "local_ip": "Yerel IP",
            "local_port": "Yerel Port", "remote_ip": "Uzak IP",
            "remote_port": "Uzak Port", "status": "Durum",
        }
        for column in columns:
            self.network_tree.heading(column, text=labels[column])
            self.network_tree.column(
                column,
                width=120 if "ip" in column else 90,
                anchor="center" if column not in {"local_ip", "remote_ip"} else "w",
            )
        self.network_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self.network_tree.yview
        )
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

    def _build_relations(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        parent.rowconfigure(3, weight=1)
        ttk.Label(parent, text="Alt işlemler", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        self.children_text = _readonly_text(parent, height=8)
        self.children_text.grid(row=1, column=0, sticky="nsew", pady=(0, 12))
        ttk.Label(parent, text="Üst işlem zinciri", style="Section.TLabel").grid(
            row=2, column=0, sticky="w", pady=(0, 6)
        )
        self.parent_chain_text = _readonly_text(parent, height=8)
        self.parent_chain_text.grid(row=3, column=0, sticky="nsew")

    def set_loading(self) -> None:
        self.loading_label.configure(text="Ayrıntılar yükleniyor…")

    def update_details(self, details: ProcessRecord) -> None:
        self.record = dict(details)
        values: dict[str, Any] = {
            **details,
            "cpu_percent": f"%{float(details.get('cpu_percent', 0)):.1f}",
            "ram_mb": f"{float(details.get('ram_mb', 0)):.1f} MB "
            f"(%{float(details.get('ram_percent', 0)):.1f})",
        }
        for key, variable in self._variables.items():
            value = values.get(key, "unknown")
            if key == "status":
                value = self.i18n.enum("process_status", value)
            variable.set(str(value))
        _set_text(self.exe_text, str(details.get("exe", t("common.unknown"))))
        _set_text(self.cwd_text, str(details.get("cwd", t("common.unknown"))))
        _set_text(
            self.command_text, str(details.get("command_line", t("common.unknown")))
        )
        _set_text(
            self.children_text,
            "\n".join(details.get("children", [])) or "Alt işlem yok.",
        )
        _set_text(
            self.parent_chain_text,
            "\n".join(details.get("parent_chain", [])) or "Üst işlem yok.",
        )
        self.network_tree.delete(*self.network_tree.get_children())
        for connection in details.get("connections", []):
            self.network_tree.insert(
                "",
                "end",
                values=tuple(
                    (
                        self.i18n.enum("network_status", connection.get(key))
                        if key == "status"
                        else connection.get(key, "—")
                    )
                    for key in (
                        "protocol", "local_ip", "local_port",
                        "remote_ip", "remote_port", "status",
                    )
                ),
            )
        self.loading_label.configure(text="Ayrıntılar güncel.")

    def _refresh(self) -> None:
        self.set_loading()
        self.on_refresh()

    def _copy(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self.loading_label.configure(text="Panoya kopyalandı.")


def _readonly_text(parent: tk.Misc, height: int) -> tk.Text:
    return tk.Text(
        parent,
        height=height,
        wrap="word",
        background="#1e293b",
        foreground="#e2e8f0",
        insertbackground="#e2e8f0",
        selectbackground="#2563eb",
        relief="flat",
        padx=8,
        pady=6,
        font=("Segoe UI", 9),
    )


def _set_text(widget: tk.Text, value: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value)
    widget.configure(state="disabled")
