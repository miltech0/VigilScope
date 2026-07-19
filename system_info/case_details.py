"""Case summary and combined evidence timeline."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import simpledialog, ttk
from typing import Any, Callable

from .detection_models import CASE_STATUSES, SEVERITIES
from .i18n import format_datetime, get_i18n, localize_widget_tree, t


class CaseDetailWindow(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        details: dict[str, Any],
        on_update: Callable[[int, dict[str, str]], None],
        on_note: Callable[[int, str], None],
        on_remove_alert: Callable[[int, int], None],
        on_export: Callable[[int], None],
    ) -> None:
        super().__init__(parent)
        self.details = details
        self.i18n = get_i18n()
        self.case_id = int(details["id"])
        self.on_update = on_update
        self.on_note = on_note
        self.title(t("cases.details_title", case_id=details["case_id"]))
        self.geometry("940x720")
        self.configure(bg="#0f172a")
        root = ttk.Frame(self, style="Root.TFrame", padding=16)
        root.pack(fill="both", expand=True)
        actions = ttk.Frame(root, style="Root.TFrame")
        actions.pack(fill="x", pady=(0, 8))
        for status in CASE_STATUSES:
            ttk.Button(
                actions,
                text=self.i18n.enum("case_status", status),
                style="Secondary.TButton",
                command=lambda value=status: on_update(
                    self.case_id,
                    {"status": value},
                ),
            ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text="Not Ekle",
            style="Secondary.TButton",
            command=self._add_note,
        ).pack(side="left", padx=8)
        ttk.Button(
            actions,
            text="Başlık / Açıklama",
            style="Secondary.TButton",
            command=self._edit_summary,
        ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text="Sonuç Yaz",
            style="Secondary.TButton",
            command=self._edit_conclusion,
        ).pack(side="left", padx=2)
        self.severity_var = tk.StringVar(
            value=self.i18n.enum("severity", details.get("severity", "info"))
        )
        self._severity_codes = {
            self.i18n.enum("severity", code): code for code in SEVERITIES
        }
        ttk.Combobox(
            actions,
            textvariable=self.severity_var,
            values=tuple(self._severity_codes),
            state="readonly",
            width=9,
        ).pack(side="left", padx=(8, 2))
        ttk.Button(
            actions,
            text="Önemi Güncelle",
            style="Secondary.TButton",
            command=lambda: on_update(
                self.case_id,
                {"severity": self._severity_codes[self.severity_var.get()]},
            ),
        ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text=t("common.export_json"),
            style="Secondary.TButton",
            command=lambda: on_export(self.case_id),
        ).pack(side="left", padx=2)
        text = tk.Text(
            root,
            wrap="word",
            background="#1e293b",
            foreground="#e2e8f0",
            relief="flat",
            font=("Consolas", 10),
        )
        text.pack(fill="both", expand=True)
        summary = {
            key: details.get(key)
            for key in (
                "case_id",
                "title",
                "description",
                "severity",
                "status",
                "created_at",
                "updated_at",
                "first_event_at",
                "last_event_at",
                "hostname",
                "summary",
                "conclusion",
            )
        }
        summary["severity"] = self.i18n.enum("severity", summary.get("severity"))
        summary["status"] = self.i18n.enum("case_status", summary.get("status"))
        for field in ("created_at", "updated_at", "first_event_at", "last_event_at"):
            summary[field] = format_datetime(summary.get(field))
        payload = {
            "özet": summary,
            "bağlı_alarmlar": details.get("alerts", []),
            "birleşik_zaman_çizelgesi": details.get("timeline", []),
            "analist_notları": details.get("notes", []),
        }
        text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")
        if details.get("alerts"):
            remove = ttk.Frame(root, style="Root.TFrame")
            remove.pack(fill="x", pady=(8, 0))
            ttk.Label(remove, text="Alarmı olaydan çıkar:", style="Filter.TLabel").pack(side="left")
            self.alert_var = tk.StringVar(
                value=str(details["alerts"][0]["id"])
            )
            ttk.Combobox(
                remove,
                textvariable=self.alert_var,
                values=[str(item["id"]) for item in details["alerts"]],
                state="readonly",
                width=10,
            ).pack(side="left", padx=6)
            ttk.Button(
                remove,
                text="İlişkiyi Kaldır",
                style="Secondary.TButton",
                command=lambda: on_remove_alert(
                    self.case_id,
                    int(self.alert_var.get()),
                ),
            ).pack(side="left")
        localize_widget_tree(self, self.i18n)

    def _add_note(self) -> None:
        note = simpledialog.askstring("Olay notu", "Not:", parent=self)
        if note:
            self.on_note(self.case_id, note)

    def _edit_summary(self) -> None:
        title = simpledialog.askstring(
            "Olay başlığı",
            "Başlık:",
            initialvalue=str(self.details.get("title", "")),
            parent=self,
        )
        if title is None:
            return
        description = simpledialog.askstring(
            "Olay açıklaması",
            "Açıklama:",
            initialvalue=str(self.details.get("description", "")),
            parent=self,
        )
        if description is not None:
            self.on_update(
                self.case_id,
                {"title": title, "description": description},
            )

    def _edit_conclusion(self) -> None:
        conclusion = simpledialog.askstring(
            "Olay sonucu",
            "Sonuç:",
            initialvalue=str(self.details.get("conclusion", "")),
            parent=self,
        )
        if conclusion is not None:
            self.on_update(self.case_id, {"conclusion": conclusion})
