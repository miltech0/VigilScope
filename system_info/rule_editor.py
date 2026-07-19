"""Data-only JSON rule editor and history preview window."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from datetime import datetime, timedelta, timezone
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable

from .i18n import localize_widget_tree, t

from .rule_loader import parse_rule_text, rule_to_json
from .rule_validator import RuleValidationError


class RuleEditorWindow(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        rule: dict[str, Any],
        readonly: bool,
        on_save: Callable[[dict[str, Any]], None],
        on_preview: Callable[
            [dict[str, Any], datetime, datetime | None],
            dict[str, Any],
        ],
    ) -> None:
        super().__init__(parent)
        self.on_save = on_save
        self.on_preview = on_preview
        self.readonly = readonly
        self._preview_queue: queue.Queue[tuple[dict[str, Any] | None, str | None]] = queue.Queue()
        self._preview_running = False
        self._preview_cancelled = False
        self.title(t("rules.details_title") if readonly else t("rules.editor_title"))
        self.geometry("900x720")
        self.configure(bg="#0f172a")
        root = ttk.Frame(self, style="Root.TFrame", padding=14)
        root.pack(fill="both", expand=True)
        toolbar = ttk.Frame(root, style="Root.TFrame")
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(
            toolbar,
            text="Kurallar yalnızca veri karşılaştırır; Python veya kabuk kodu çalıştıramaz.",
            style="Status.TLabel",
        ).pack(side="left", expand=True, anchor="w")
        self._range_labels = {
            t("history.last_15_minutes"): 900,
            t("history.last_1_hour"): 3600,
            t("history.last_24_hours"): 86400,
            t("history.last_7_days"): 604800,
        }
        self._custom_range_label = t("history.custom_range")
        self.range_var = tk.StringVar(value=t("history.last_24_hours"))
        ttk.Combobox(
            toolbar,
            textvariable=self.range_var,
            values=(*self._range_labels, self._custom_range_label),
            state="readonly",
            width=15,
        ).pack(side="left", padx=4)
        ttk.Button(
            toolbar,
            text="Geçmişte Test Et",
            style="Secondary.TButton",
            command=self._preview,
        ).pack(side="left", padx=4)
        ttk.Button(
            toolbar,
            text="Önizlemeyi İptal Et",
            style="Secondary.TButton",
            command=self._cancel_preview,
        ).pack(side="left", padx=2)
        if not readonly:
            ttk.Button(
                toolbar,
                text="Doğrula ve Kaydet",
                style="Refresh.TButton",
                command=self._save,
            ).pack(side="left")
        self.text = tk.Text(
            root,
            wrap="none",
            background="#1e293b",
            foreground="#e2e8f0",
            insertbackground="#f8fafc",
            selectbackground="#2563eb",
            relief="flat",
            font=("Consolas", 10),
        )
        self.text.pack(fill="both", expand=True)
        clean = {key: value for key, value in rule.items() if key != "_metadata"}
        self.text.insert("1.0", rule_to_json(clean))
        if readonly:
            self.text.configure(state="disabled")
        localize_widget_tree(self)

    def _read_rule(self) -> dict[str, Any] | None:
        text = self.text.get("1.0", "end") if not self.readonly else rule_to_json(
            {key: value for key, value in self._current_payload().items() if key != "_metadata"}
        )
        try:
            return parse_rule_text(text)
        except RuleValidationError as exc:
            messagebox.showerror("Kural doğrulama hatası", str(exc), parent=self)
            return None

    def _current_payload(self) -> dict[str, Any]:
        state = str(self.text.cget("state"))
        if state == "disabled":
            self.text.configure(state="normal")
        try:
            return json.loads(self.text.get("1.0", "end"))
        finally:
            if state == "disabled":
                self.text.configure(state="disabled")

    def _save(self) -> None:
        rule = self._read_rule()
        if rule:
            self.on_save(rule)

    def _preview(self) -> None:
        if self._preview_running:
            messagebox.showinfo(
                "Geçmiş kural testi",
                "Bir önizleme zaten sürüyor.",
                parent=self,
            )
            return
        try:
            rule = parse_rule_text(json.dumps(self._current_payload(), ensure_ascii=False))
        except RuleValidationError as exc:
            messagebox.showerror("Kural doğrulama hatası", str(exc), parent=self)
            return
        until: datetime | None = None
        if self.range_var.get() == self._custom_range_label:
            start_text = simpledialog.askstring(
                "Özel tarih aralığı",
                "Başlangıç (YYYY-AA-GG SS:DD):",
                parent=self,
            )
            end_text = simpledialog.askstring(
                "Özel tarih aralığı",
                "Bitiş (YYYY-AA-GG SS:DD):",
                parent=self,
            )
            if not start_text or not end_text:
                return
            try:
                local_zone = datetime.now().astimezone().tzinfo
                since = datetime.strptime(start_text, "%Y-%m-%d %H:%M").replace(
                    tzinfo=local_zone
                ).astimezone(timezone.utc)
                until = datetime.strptime(end_text, "%Y-%m-%d %H:%M").replace(
                    tzinfo=local_zone
                ).astimezone(timezone.utc)
                if until < since:
                    raise ValueError
            except ValueError:
                messagebox.showerror(
                    "Özel tarih aralığı",
                    "Tarih biçimi veya sırası geçersiz.",
                    parent=self,
                )
                return
        else:
            seconds = self._range_labels[self.range_var.get()]
            since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        self._preview_running = True
        self._preview_cancelled = False

        def worker() -> None:
            try:
                result = self.on_preview(rule, since, until)
                self._preview_queue.put((result, None))
            except Exception as exc:
                self._preview_queue.put((None, str(exc)))

        threading.Thread(
            target=worker,
            name="rule-preview",
            daemon=True,
        ).start()
        self.after(100, self._poll_preview)

    def _poll_preview(self) -> None:
        try:
            result, error = self._preview_queue.get_nowait()
        except queue.Empty:
            if self._preview_running:
                self.after(100, self._poll_preview)
            return
        self._preview_running = False
        if self._preview_cancelled:
            return
        if error or result is None:
            messagebox.showerror(
                "Geçmiş kural testi",
                error or "Önizleme tamamlanamadı.",
                parent=self,
            )
            return
        messagebox.showinfo(
            "Geçmiş kural testi",
            (
                f"Toplam eşleşme: {result['total_matches']}\n"
                f"Olası alarm: {result['possible_alerts']}\n"
                f"İlk eşleşme: {result['first_match'] or '—'}\n"
                f"Son eşleşme: {result['last_match'] or '—'}\n"
                f"Limit uygulandı: {'Evet' if result['truncated'] else 'Hayır'}\n\n"
                "Bu önizleme alarm veya checkpoint oluşturmadı."
            ),
            parent=self,
        )

    def _cancel_preview(self) -> None:
        if self._preview_running:
            self._preview_cancelled = True
