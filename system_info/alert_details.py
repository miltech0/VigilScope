"""Alert summary, evidence timeline, notes, and status actions."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import simpledialog, ttk
from typing import Any, Callable

from .detection_models import ALERT_STATUSES
from .i18n import format_datetime, get_i18n, localize_widget_tree, t


class AlertDetailWindow(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        details: dict[str, Any],
        on_status: Callable[[int, str, str], None],
        on_note: Callable[[int, str], None],
        on_create_case: Callable[[int], None],
        on_export: Callable[[int], None],
    ) -> None:
        super().__init__(parent)
        self.details = details
        self.i18n = get_i18n()
        self.alert_id = int(details["id"])
        self.on_status = on_status
        self.on_note = on_note
        self.title(t("alerts.details_title", rule_id=details["rule_id"]))
        self.geometry("980x760")
        self.minsize(760, 560)
        self.configure(bg="#0f172a")
        root = ttk.Frame(self, style="Root.TFrame", padding=16)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        ttk.Label(
            root,
            text=t("messages.alerts_disclaimer"),
            style="Status.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        actions = ttk.Frame(root, style="Root.TFrame")
        actions.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        for status in ALERT_STATUSES[1:]:
            ttk.Button(
                actions,
                text=self.i18n.enum("alert_status", status),
                style="Secondary.TButton",
                command=lambda value=status: self._set_status(value),
            ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text=t("alerts.reopen"),
            style="Secondary.TButton",
            command=lambda: self._set_status("new"),
        ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text="Not Ekle",
            style="Secondary.TButton",
            command=self._add_note,
        ).pack(side="left", padx=8)
        ttk.Button(
            actions,
            text="Olay Dosyası Oluştur",
            style="Secondary.TButton",
            command=lambda: on_create_case(self.alert_id),
        ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text=t("common.export_json"),
            style="Secondary.TButton",
            command=lambda: on_export(self.alert_id),
        ).pack(side="left", padx=2)

        notebook = ttk.Notebook(root)
        notebook.grid(row=2, column=0, sticky="nsew")
        summary = ttk.Frame(notebook, style="Root.TFrame", padding=10)
        timeline = ttk.Frame(notebook, style="Root.TFrame", padding=10)
        notes = ttk.Frame(notebook, style="Root.TFrame", padding=10)
        notebook.add(summary, text="Özet ve Kural")
        notebook.add(timeline, text="Kanıt Zaman Çizelgesi")
        notebook.add(notes, text="Notlar ve Geçmiş")
        self._json_text(summary, _summary_payload(details, self.i18n))
        self._timeline_text(timeline, details.get("evidence", []))
        self._json_text(
            notes,
            {
                "analist_notları": details.get("notes", []),
                "durum_geçmişi": details.get("status_history", []),
                "ilgili_alarmlar": details.get("related_alerts", []),
                "olay_dosyası": details.get("case_id"),
            },
        )

        copy = ttk.Frame(root, style="Root.TFrame")
        copy.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        for label, value in (
            ("Alarm Kimliği", str(details["id"])),
            ("PID", str(details.get("pid", "—"))),
            ("Dosya Yolu", str(details.get("executable_path", "Bilinmiyor"))),
            ("Komut Satırı", str(details.get("masked_command_line", "Bilinmiyor"))),
            ("IP Adresi", str(details.get("remote_ip", "—"))),
            ("Kanıt Özeti", str(details.get("evidence_summary", ""))),
        ):
            ttk.Button(
                copy,
                text=f"{label} Kopyala",
                style="Secondary.TButton",
                command=lambda text=value: self._copy(text),
            ).pack(side="left", padx=2)
        localize_widget_tree(self, self.i18n)

    def _set_status(self, status: str) -> None:
        note = simpledialog.askstring(
            "Durum açıklaması",
            "İsteğe bağlı açıklama/not:",
            parent=self,
        ) or ""
        self.on_status(self.alert_id, status, note)

    def _add_note(self) -> None:
        note = simpledialog.askstring(
            "Analist notu",
            "Alarm notu:",
            parent=self,
        )
        if note:
            self.on_note(self.alert_id, note)

    def _copy(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)

    @staticmethod
    def _json_text(parent: ttk.Frame, payload: Any) -> None:
        text = _text(parent)
        text.pack(fill="both", expand=True)
        text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")

    @staticmethod
    def _timeline_text(parent: ttk.Frame, evidence: list[dict[str, Any]]) -> None:
        text = _text(parent)
        text.pack(fill="both", expand=True)
        if not evidence:
            text.insert("1.0", "Bu alarm için kanıt bulunamadı.")
        else:
            for item in evidence:
                text.insert(
                    "end",
                    f"{item.get('timestamp', '—')}  "
                    f"[{item.get('source_table', '—')}:{item.get('source_record_id', '—')}]  "
                    f"{item.get('summary', '')}\n",
                )
        text.configure(state="disabled")


def _text(parent: tk.Misc) -> tk.Text:
    return tk.Text(
        parent,
        wrap="word",
        background="#1e293b",
        foreground="#e2e8f0",
        selectbackground="#2563eb",
        relief="flat",
        padx=10,
        pady=10,
        font=("Consolas", 10),
    )


def _summary_payload(details: dict[str, Any], i18n: Any) -> dict[str, Any]:
    rule = details.get("rule", {})
    alert = {
        key: details.get(key)
        for key in (
            "id",
            "rule_id",
            "title",
            "description",
            "severity",
            "status",
            "first_seen",
            "last_seen",
            "occurrence_count",
            "hostname",
            "username",
            "process_name",
            "pid",
            "process_create_time",
            "parent_process_name",
            "executable_path",
            "masked_command_line",
            "local_address",
            "remote_address",
            "expected_behavior",
            "expected_note",
        )
    }
    rule_id = str(details.get("rule_id", ""))
    if rule_id:
        alert["title"] = i18n.optional(
            f"rules.{rule_id}.title",
            str(alert.get("title") or ""),
        )
        alert["description"] = i18n.optional(
            f"rules.{rule_id}.description",
            str(alert.get("description") or ""),
        )
    alert["severity"] = i18n.enum("severity", alert.get("severity"))
    alert["status"] = i18n.enum("alert_status", alert.get("status"))
    for field in ("first_seen", "last_seen", "process_create_time"):
        alert[field] = format_datetime(alert.get(field))
    return {
        "alarm": alert,
        "mitre_attack": rule.get("mitre_attack", []),
        "mitre_notu": "ATT&CK eşleştirmesi davranış sınıflandırmasıdır; saldırı kanıtı değildir.",
        "yanlış_pozitifler": rule.get("false_positives", []),
        "inceleme_adımları": rule.get("investigation_steps", []),
    }
