"""Read-only selectable details for a network record."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Any

from .i18n import format_datetime, get_i18n, localize_widget_tree, t


class NetworkDetailWindow(tk.Toplevel):
    def __init__(self, parent: tk.Misc, record: dict[str, Any], kind: str) -> None:
        super().__init__(parent)
        self.record = record
        self.i18n = get_i18n()
        titles = {
            "listener": t("tabs.listening_ports"),
            "endpoint": t("tabs.remote_endpoints"),
            "event": t("tabs.network_events"),
            "finding": t("tabs.findings"),
        }
        self.title(f"{titles.get(kind, t('common.details'))} — {t('common.details')}")
        self.geometry("820x680")
        self.minsize(650, 520)
        self.configure(bg="#0f172a")
        self.transient(parent)
        root = ttk.Frame(self, style="Root.TFrame", padding=18)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)
        actions = ttk.Frame(root, style="Root.TFrame")
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(
            actions,
            text=t("messages.passive_notice"),
            style="Status.TLabel",
        ).pack(side="left", expand=True, anchor="w")
        for label, value in (
            ("IP ve Portu Kopyala", _address(record)),
            ("PID Kopyala", str(record.get("pid", record.get("last_pid", "—")))),
            ("Dosya Yolunu Kopyala", str(record.get("process_path", "Bilinmiyor"))),
            ("Komut Satırını Kopyala", str(record.get("command_line", "Bilinmiyor"))),
        ):
            ttk.Button(
                actions,
                text=label,
                style="Secondary.TButton",
                command=lambda text=value: self._copy(text),
            ).pack(side="left", padx=3)
        text = tk.Text(
            root,
            wrap="word",
            background="#1e293b",
            foreground="#e2e8f0",
            selectbackground="#2563eb",
            relief="flat",
            padx=12,
            pady=10,
            font=("Consolas", 10),
        )
        text.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(root, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=1, sticky="ns")
        payload = dict(record)
        enum_fields = {
            "event_type": "event_type",
            "address_scope": "address_scope",
            "ip_class": "address_scope",
            "severity": "severity",
            "status": "finding_status" if kind == "finding" else "network_status",
        }
        for field, domain in enum_fields.items():
            if payload.get(field) not in (None, ""):
                payload[field] = self.i18n.enum(domain, payload[field])
        for field in ("timestamp", "first_seen", "last_seen", "updated_at"):
            if payload.get(field):
                payload[field] = format_datetime(payload[field])
        for key in ("details_json", "evidence_json"):
            value = payload.get(key)
            if isinstance(value, str):
                try:
                    payload[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")
        localize_widget_tree(self)

    def _copy(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)


def _address(record: dict[str, Any]) -> str:
    ip = record.get("local_ip") or record.get("remote_ip") or "—"
    port = record.get("local_port") or record.get("remote_port") or "—"
    return f"{ip}:{port}"
