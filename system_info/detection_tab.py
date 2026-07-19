"""Detections tab for alerts, cases, rules, ATT&CK, and suppressions."""

from __future__ import annotations

import json
import tkinter as tk
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Callable

from .detection_models import ALERT_STATUSES, SEVERITIES
from .i18n import get_i18n, t
from .network_tab import SortableTable
from .rule_editor import RuleEditorWindow
from .rule_loader import (
    load_single_rule_file,
    localized_builtin_rule,
    rule_to_json,
)
from .rule_validator import RuleValidationError


class DetectionTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        on_refresh: Callable[[], None],
        on_details: Callable[[dict[str, Any], str], None],
        on_action: Callable[[str, dict[str, Any]], Any],
        on_preview: Callable[
            [dict[str, Any], datetime, datetime | None],
            dict[str, Any],
        ],
        on_export_all: Callable[[str], None],
    ) -> None:
        super().__init__(parent, style="Root.TFrame", padding=(4, 16, 4, 4))
        self.on_refresh = on_refresh
        self.on_details = on_details
        self.on_action = on_action
        self.on_preview = on_preview
        self.on_export_all = on_export_all
        self.i18n = get_i18n()
        self.data: dict[str, Any] = {}
        self.notifications_muted = tk.BooleanVar(value=False)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        top = ttk.Frame(self, style="Root.TFrame")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        top.columnconfigure(0, weight=1)
        ttk.Label(
            top,
            text=t("messages.alerts_disclaimer"),
            style="Status.TLabel",
        ).grid(row=0, column=0, sticky="w")
        self.badge_var = tk.StringVar(
            value=t("detections.new_high_critical", count=0)
        )
        ttk.Label(top, textvariable=self.badge_var, style="Status.TLabel").grid(
            row=0, column=1, padx=8
        )
        ttk.Checkbutton(
            top,
            text="Bildirimleri sessize al",
            variable=self.notifications_muted,
        ).grid(row=0, column=2, padx=8)
        ttk.Button(
            top,
            text=t("common.export_csv"),
            style="Secondary.TButton",
            command=lambda: on_export_all("csv"),
        ).grid(row=0, column=3, padx=3)
        ttk.Button(
            top,
            text=t("common.export_json"),
            style="Secondary.TButton",
            command=lambda: on_export_all("json"),
        ).grid(row=0, column=4, padx=3)
        ttk.Button(
            top,
            text=t("common.refresh"),
            style="Refresh.TButton",
            command=on_refresh,
        ).grid(row=0, column=5, padx=(8, 0))
        self.views = ttk.Notebook(self)
        self.views.grid(row=1, column=0, sticky="nsew")
        self._build_overview()
        self._build_alerts()
        self._build_cases()
        self._build_rules()
        self._build_attack()
        self._build_suppressions()

    def _tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self.views, style="Root.TFrame", padding=12)
        self.views.add(frame, text=title)
        return frame

    def _build_overview(self) -> None:
        parent = self._tab(t("tabs.overview"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        cards = ttk.Frame(parent, style="Root.TFrame")
        cards.grid(row=0, column=0, sticky="ew")
        labels = (
            ("new", "Yeni alarm"),
            ("review", "İncelenen"),
            ("high", "Yüksek / Kritik"),
            ("last24", "Son 24 saat"),
            ("rules", "Etkin kural"),
            ("suppressed", "Susturulan"),
            ("cases", "Açık olay"),
        )
        self.summary_vars: dict[str, tk.StringVar] = {}
        for index, (key, label) in enumerate(labels):
            cards.columnconfigure(index, weight=1)
            card = ttk.Frame(cards, style="Card.TFrame", padding=10)
            card.grid(row=0, column=index, sticky="nsew", padx=3)
            ttk.Label(card, text=label, style="CardTitle.TLabel").pack()
            value = tk.StringVar(value="0")
            self.summary_vars[key] = value
            ttk.Label(card, textvariable=value, style="Metric.TLabel").pack()
        lists = ttk.Frame(parent, style="Root.TFrame")
        lists.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        self.overview_texts: dict[str, tk.Text] = {}
        for index, (key, title) in enumerate(
            (
                ("recent", "En son alarmlar"),
                ("rules", "En sık eşleşen kurallar"),
                ("processes", "En çok alarm üreten işlemler"),
                ("severity", "Önem dağılımı"),
                ("attack", "ATT&CK taktik dağılımı"),
            )
        ):
            lists.columnconfigure(index, weight=1)
            box = ttk.Frame(lists, style="Card.TFrame", padding=8)
            box.grid(row=0, column=index, sticky="nsew", padx=3)
            ttk.Label(box, text=title, style="CardTitle.TLabel").pack(anchor="w")
            text = _text(box, 14)
            text.pack(fill="both", expand=True, pady=(6, 0))
            self.overview_texts[key] = text

    def _build_alerts(self) -> None:
        parent = self._tab(t("tabs.alerts"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        filters = ttk.Frame(parent, style="Root.TFrame")
        filters.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filters.columnconfigure(1, weight=1)
        self.alert_search = tk.StringVar()
        ttk.Label(
            filters,
            text="Kural / işlem / kullanıcı / PID / IP",
            style="Filter.TLabel",
        ).grid(row=0, column=0)
        entry = ttk.Entry(filters, textvariable=self.alert_search)
        entry.grid(row=0, column=1, sticky="ew", padx=6)
        entry.bind("<KeyRelease>", self._filter_alerts)
        self._severity_codes = {
            t("common.all"): "all",
            **{self.i18n.enum("severity", code): code for code in SEVERITIES},
        }
        self._alert_status_codes = {
            t("common.all"): "all",
            **{self.i18n.enum("alert_status", code): code for code in ALERT_STATUSES},
        }
        self.alert_severity = _combo(
            filters, tuple(self._severity_codes), 2, self._filter_alerts
        )
        self.alert_status = _combo(
            filters, tuple(self._alert_status_codes), 3, self._filter_alerts
        )
        self.alert_category = _combo(filters, (t("common.all"),), 4, self._filter_alerts)
        self.alert_time = _combo(
            filters,
            ("Tüm zamanlar", "Son 15 dakika", "Son 1 saat", "Son 24 saat", "Son 7 gün"),
            5,
            self._filter_alerts,
            "Son 24 saat",
        )
        self.only_new = tk.BooleanVar()
        ttk.Checkbutton(
            filters,
            text="Yalnızca yeni",
            variable=self.only_new,
            command=self._filter_alerts,
        ).grid(row=0, column=6, padx=6)
        columns = {
            "first_seen": ("İlk Görülme", 150, False),
            "last_seen": ("Son Görülme", 150, False),
            "severity_display": (t("columns.severity"), 80, False),
            "status_display": (t("columns.status"), 105, False),
            "rule_id": (t("columns.rule_id"), 85, False),
            "title": (t("columns.title"), 260, False),
            "process_name": (t("common.process"), 145, False),
            "pid": (t("columns.pid"), 70, True),
            "username": (t("columns.username"), 135, False),
            "remote_address": (t("common.remote_address"), 165, False),
            "occurrence_count": ("Tekrar", 70, True),
        }
        self.alert_table = SortableTable(parent, columns, self.on_details, "alert")
        self.alert_table.grid(row=1, column=0, sticky="nsew")
        actions = ttk.Frame(parent, style="Root.TFrame")
        actions.grid(row=2, column=0, sticky="e", pady=(7, 0))
        for text, status in (
            (self.i18n.enum("alert_status", "investigating"), "investigating"),
            (self.i18n.enum("alert_status", "confirmed"), "confirmed"),
            (self.i18n.enum("alert_status", "false_positive"), "false_positive"),
            (t("common.close"), "closed"),
        ):
            ttk.Button(
                actions,
                text=text,
                style="Secondary.TButton",
                command=lambda value=status: self._alert_status(value),
            ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text="Not Ekle",
            style="Secondary.TButton",
            command=self._alert_note,
        ).pack(side="left", padx=5)
        ttk.Button(
            actions,
            text="Olay Oluştur",
            style="Secondary.TButton",
            command=self._create_case_from_alert,
        ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text="Mevcut Olaya Ekle",
            style="Secondary.TButton",
            command=self._add_alert_to_case,
        ).pack(side="left", padx=2)
        ttk.Button(
            actions,
            text="Bu Davranışı Sustur",
            style="Secondary.TButton",
            command=self._suppress_alert,
        ).pack(side="left", padx=2)

    def _build_cases(self) -> None:
        parent = self._tab(t("tabs.cases"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        header = ttk.Frame(parent, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(
            header,
            text="Olay dosyaları veriyi silmez; seçilen alarmları inceleme bağlamında ilişkilendirir.",
            style="Status.TLabel",
        ).pack(side="left")
        columns = {
            "case_id": ("Olay Kimliği", 150, False),
            "title": ("Başlık", 260, False),
            "severity_display": (t("columns.severity"), 80, False),
            "status_display": (t("columns.status"), 100, False),
            "created_at": ("Oluşturulma", 150, False),
            "updated_at": ("Son Güncelleme", 150, False),
            "first_event_at": ("İlk Olay", 150, False),
            "last_event_at": ("Son Olay", 150, False),
            "alert_count": ("Alarm", 70, True),
        }
        self.case_table = SortableTable(parent, columns, self.on_details, "case")
        self.case_table.grid(row=1, column=0, sticky="nsew")

    def _build_rules(self) -> None:
        parent = self._tab(t("tabs.rules"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        actions = ttk.Frame(parent, style="Root.TFrame")
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(
            actions,
            text="Dahili kurallar silinemez; tüm kurallar güvenli JSON verisidir.",
            style="Status.TLabel",
        ).pack(side="left", expand=True, anchor="w")
        for text, command in (
            ("Etkinleştir / Devre Dışı", self._toggle_rule),
            ("Ayrıntı / Düzenle", self._edit_rule),
            ("Yeni Kullanıcı Kuralı", self._new_rule),
            ("İçe Aktar", self._import_rule),
            ("Dışa Aktar", self._export_rule),
            ("Kullanıcı Kuralını Sil", self._delete_rule),
        ):
            ttk.Button(
                actions,
                text=text,
                style="Secondary.TButton",
                command=command,
            ).pack(side="left", padx=2)
        columns = {
            "id": ("Kural", 95, False),
            "title": ("Başlık", 310, False),
            "enabled_text": ("Etkin", 65, False),
            "severity_display": (t("columns.severity"), 80, False),
            "category": (t("columns.category"), 180, False),
            "version": ("Sürüm", 70, False),
            "last_match_at": ("Son Eşleşme", 150, False),
            "match_count": ("Toplam", 70, True),
            "mitre_text": ("MITRE Tekniği", 190, False),
        }
        self.rule_table = SortableTable(parent, columns, self.on_details, "rule")
        self.rule_table.grid(row=1, column=0, sticky="nsew")

    def _build_attack(self) -> None:
        parent = self._tab(t("tabs.attack_coverage"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        ttk.Label(
            parent,
            text="Bu görünüm kurumsal güvenlik kapsamı iddiası değil, yalnızca etkin kuralların davranış sınıflandırmasıdır.",
            style="Status.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        columns = {
            "tactics_text": ("Taktik", 260, False),
            "techniques_text": ("Teknik / Alt Teknik", 350, False),
            "enabled_rule_count": ("Etkin Kural", 90, True),
            "count_24h": ("24 Saat Alarm", 100, True),
            "total_count": ("Toplam Alarm", 100, True),
        }
        self.attack_table = SortableTable(parent, columns, self.on_details, "attack")
        self.attack_table.grid(row=1, column=0, sticky="nsew")

    def _build_suppressions(self) -> None:
        parent = self._tab(t("tabs.suppressions"))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        actions = ttk.Frame(parent, style="Root.TFrame")
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(
            actions,
            text="Susturma kaynak olayları veya eski alarmları silmez.",
            style="Status.TLabel",
        ).pack(side="left", expand=True, anchor="w")
        ttk.Button(
            actions,
            text="Etkinleştir / Devre Dışı",
            style="Secondary.TButton",
            command=self._toggle_suppression,
        ).pack(side="left", padx=3)
        ttk.Button(
            actions,
            text="Yeni Susturma",
            style="Secondary.TButton",
            command=self._new_suppression,
        ).pack(side="left")
        ttk.Button(
            actions,
            text="Seçileni Sil",
            style="Secondary.TButton",
            command=self._delete_suppression,
        ).pack(side="left", padx=3)
        columns = {
            "id": ("ID", 60, True),
            "name": ("Ad", 220, False),
            "enabled_text": ("Etkin", 65, False),
            "created_at": ("Oluşturulma", 150, False),
            "expires_at": ("Bitiş", 150, False),
            "reason": ("Neden", 280, False),
            "occurrence_count": ("Eşleşme", 80, True),
            "last_matched_at": ("Son Eşleşme", 150, False),
        }
        self.suppression_table = SortableTable(
            parent, columns, self.on_details, "suppression"
        )
        self.suppression_table.grid(row=1, column=0, sticky="nsew")

    def set_data(self, data: dict[str, Any]) -> None:
        self.data = data
        alerts = data.get("alerts", [])
        rules = data.get("rules", [])
        cases = data.get("cases", [])
        suppressions = data.get("suppressions", [])
        coverage = _coverage_rows(rules, data.get("attack_coverage", []))
        for item in alerts:
            item["_stable_key"] = item["id"]
            rule_id = str(item.get("rule_id", ""))
            item["title"] = self.i18n.optional(
                f"rules.{rule_id}.title", str(item.get("title", ""))
            )
            item["description"] = self.i18n.optional(
                f"rules.{rule_id}.description", str(item.get("description", ""))
            )
            item["category_display"] = self.i18n.optional(
                f"rules.{rule_id}.category", str(item.get("category", ""))
            )
            item["severity_display"] = self.i18n.enum(
                "severity", item.get("severity")
            )
            item["status_display"] = self.i18n.enum(
                "alert_status", item.get("status")
            )
        categories = sorted({str(item["category"]) for item in alerts})
        self._category_codes = {
            t("common.all"): "all",
            **{
                next(
                    (
                        str(item["category_display"])
                        for item in alerts
                        if item["category"] == category
                    ),
                    category,
                ): category
                for category in categories
            },
        }
        self.alert_category.configure(values=tuple(self._category_codes))
        if self.alert_category.get() not in self._category_codes:
            self.alert_category.set(t("common.all"))
        for rule in rules:
            localized = localized_builtin_rule(rule, self.i18n)
            rule.update(localized)
            meta = rule.get("_metadata", {})
            rule["_stable_key"] = rule["id"]
            rule["enabled_text"] = t("common.yes") if rule.get("enabled") else t("common.no")
            rule["severity_display"] = self.i18n.enum(
                "severity", rule.get("severity")
            )
            rule["last_match_at"] = meta.get("last_match_at") or "—"
            rule["match_count"] = meta.get("match_count", 0)
            rule["mitre_text"] = ", ".join(
                str(item.get("technique_id", ""))
                for item in rule.get("mitre_attack", [])
                if item.get("technique_id")
            ) or "—"
        for item in cases:
            item["_stable_key"] = item["id"]
            item["severity_display"] = self.i18n.enum(
                "severity", item.get("severity")
            )
            item["status_display"] = self.i18n.enum(
                "case_status", item.get("status")
            )
        for item in suppressions:
            item["_stable_key"] = item["id"]
            item["enabled_text"] = t("common.yes") if item.get("enabled") else t("common.no")
            item["expires_at"] = item.get("expires_at") or t("common.indefinite")
        self.alert_table.records = alerts
        self.rule_table.records = rules
        self.case_table.records = cases
        self.suppression_table.records = suppressions
        self.attack_table.records = coverage
        self._filter_alerts()
        self.rule_table.render(rules)
        self.case_table.render(cases)
        self.suppression_table.render(suppressions)
        self.attack_table.render(coverage)
        self._update_overview()

    def set_notification_count(self, count: int) -> None:
        self.badge_var.set(t("detections.new_high_critical", count=count))

    def _filter_alerts(self, _event: tk.Event | None = None) -> None:
        needle = self.alert_search.get().casefold()
        cutoff = _cutoff(self.alert_time.get())
        records = [
            item
            for item in self.alert_table.records
            if (
                not needle
                or needle
                in " ".join(
                    str(item.get(key, ""))
                    for key in (
                        "rule_id",
                        "category",
                        "process_name",
                        "username",
                        "pid",
                        "remote_address",
                        "mitre_tactics",
                    )
                ).casefold()
            )
            and (
                self._severity_codes.get(self.alert_severity.get(), "all") == "all"
                or item["severity"] == self._severity_codes.get(self.alert_severity.get())
            )
            and (
                self._alert_status_codes.get(self.alert_status.get(), "all") == "all"
                or item["status"] == self._alert_status_codes.get(self.alert_status.get())
            )
            and (
                self._category_codes.get(self.alert_category.get(), "all") == "all"
                or item["category"] == self._category_codes.get(self.alert_category.get())
            )
            and (not self.only_new.get() or item["status"] == "new")
            and (
                cutoff is None
                or _parse_time(str(item["last_seen"])) >= cutoff
            )
        ]
        self.alert_table.render(records)

    def _update_overview(self) -> None:
        alerts = self.data.get("alerts", [])
        rules = self.data.get("rules", [])
        cases = self.data.get("cases", [])
        suppressions = self.data.get("suppressions", [])
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        values = {
            "new": sum(item["status"] == "new" for item in alerts),
            "review": sum(item["status"] == "investigating" for item in alerts),
            "high": sum(item["severity"] in {"high", "critical"} for item in alerts),
            "last24": sum(_parse_time(item["last_seen"]) >= cutoff for item in alerts),
            "rules": sum(bool(item.get("enabled")) for item in rules),
            "suppressed": sum(int(item.get("occurrence_count", 0)) for item in suppressions),
            "cases": sum(item["status"] not in {"resolved", "closed", "false_positive"} for item in cases),
        }
        for key, value in values.items():
            self.summary_vars[key].set(str(value))
        _set_text(
            self.overview_texts["recent"],
            "\n".join(
                f"[{item['severity_display']}] {item['rule_id']} — {item['process_name']}"
                for item in alerts[:8]
            )
            or "Veri yok.",
        )
        _set_text(
            self.overview_texts["rules"],
            _rank(Counter(item["rule_id"] for item in alerts)),
        )
        _set_text(
            self.overview_texts["processes"],
            _rank(Counter(item["process_name"] for item in alerts)),
        )
        _set_text(
            self.overview_texts["severity"],
            _rank(Counter(item["severity_display"] for item in alerts)),
        )
        tactics: Counter[str] = Counter()
        for item in alerts:
            try:
                tactics.update(json.loads(item.get("mitre_tactics", "[]")))
            except json.JSONDecodeError:
                pass
        _set_text(self.overview_texts["attack"], _rank(tactics))

    def _selected_alert(self) -> dict[str, Any] | None:
        return self.alert_table.selected_record()

    def _alert_status(self, status: str) -> None:
        record = self._selected_alert()
        if record:
            self.on_action("alert_status", {"id": record["id"], "status": status, "note": ""})

    def _alert_note(self) -> None:
        record = self._selected_alert()
        if not record:
            return
        note = simpledialog.askstring("Analist notu", "Not:", parent=self)
        if note:
            self.on_action("alert_note", {"id": record["id"], "note": note})

    def _create_case_from_alert(self) -> None:
        record = self._selected_alert()
        if not record:
            return
        title = simpledialog.askstring(
            "Yeni olay dosyası",
            "Olay başlığı:",
            parent=self,
            initialvalue=f"{record['rule_id']} incelemesi",
        )
        if title:
            self.on_action(
                "case_create",
                {
                    "title": title,
                    "description": record["description"],
                    "severity": record["severity"],
                    "alert_ids": [record["id"]],
                },
            )

    def _add_alert_to_case(self) -> None:
        record = self._selected_alert()
        if not record:
            return
        cases = self.data.get("cases", [])
        if not cases:
            messagebox.showinfo("Olay dosyası", "Önce bir olay dosyası oluşturun.", parent=self)
            return
        value = simpledialog.askinteger(
            "Olaya alarm ekle",
            "Olay veritabanı ID'si:\n"
            + "\n".join(f"{item['id']}: {item['case_id']} — {item['title']}" for item in cases[:20]),
            parent=self,
        )
        if value:
            self.on_action("case_add_alert", {"case_id": value, "alert_id": record["id"]})

    def _suppress_alert(self) -> None:
        record = self._selected_alert()
        if not record:
            return
        reason = simpledialog.askstring(
            "Davranışı sustur",
            "Susturma nedeni:",
            parent=self,
        )
        if not reason:
            return
        conditions = {
            "all": [
                {"field": "rule_id", "operator": "equals", "value": record["rule_id"]},
                {"field": "process_name", "operator": "equals", "value": record["process_name"]},
                {"field": "pid", "operator": "equals", "value": record["pid"]},
                {
                    "field": "process_create_time",
                    "operator": "equals",
                    "value": record.get("process_create_time"),
                },
            ]
        }
        self.on_action(
            "suppression_create",
            {
                "name": f"{record['rule_id']} / {record['process_name']}",
                "conditions": conditions,
                "reason": reason,
                "expires_at": None,
            },
        )

    def _selected_rule(self) -> dict[str, Any] | None:
        return self.rule_table.selected_record()

    def _toggle_rule(self) -> None:
        rule = self._selected_rule()
        if rule:
            self.on_action(
                "rule_toggle",
                {"id": rule["id"], "enabled": not bool(rule.get("enabled"))},
            )

    def _edit_rule(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        readonly = bool(rule.get("_metadata", {}).get("is_builtin"))
        RuleEditorWindow(
            self,
            rule,
            readonly,
            lambda item: self.on_action("rule_save", {"rule": item}),
            self.on_preview,
        )

    def _new_rule(self) -> None:
        template = {
            "id": "USER-001",
            "title": "Yeni kullanıcı kuralı",
            "description": "Açıklanabilir yerel gözlem kuralı.",
            "enabled": True,
            "severity": "info",
            "category": "Kullanıcı",
            "event_types": ["process_started"],
            "conditions": {
                "field": "process_name",
                "operator": "equals",
                "value": "ornek.exe",
            },
            "group_by": ["pid", "process_create_time"],
            "deduplication": {"fields": ["pid", "process_create_time"]},
            "mitre_attack": [],
            "false_positives": ["Meşru örnek uygulama."],
            "investigation_steps": ["İşlem ayrıntılarını doğrulayın."],
            "tags": ["user"],
            "version": "1.0",
        }
        RuleEditorWindow(
            self,
            template,
            False,
            lambda item: self.on_action("rule_save", {"rule": item}),
            self.on_preview,
        )

    def _import_rule(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="JSON kuralı içe aktar",
            filetypes=[("JSON", "*.json"), ("Tüm dosyalar", "*.*")],
        )
        if not path:
            return
        try:
            rule = load_single_rule_file(path)
        except (OSError, RuleValidationError) as exc:
            messagebox.showerror("Kural içe aktarma", str(exc), parent=self)
            return
        messagebox.showinfo(
            "Doğrulama başarılı",
            f"{rule['id']} kuralı geçerli. Kaydetmeden önce düzenleyebilirsiniz.",
            parent=self,
        )
        RuleEditorWindow(
            self,
            rule,
            False,
            lambda item: self.on_action("rule_save", {"rule": item}),
            self.on_preview,
        )

    def _export_rule(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if path:
            clean = {key: value for key, value in rule.items() if key != "_metadata"}
            Path(path).write_text(rule_to_json(clean), encoding="utf-8")

    def _delete_rule(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        if rule.get("_metadata", {}).get("is_builtin"):
            messagebox.showwarning(
                "Dahili kural",
                "Dahili kurallar silinemez; devre dışı bırakabilirsiniz.",
                parent=self,
            )
            return
        if messagebox.askyesno(
            "Kuralı sil",
            f"{rule['id']} kullanıcı kuralı silinsin mi?",
            parent=self,
        ):
            self.on_action("rule_delete", {"id": rule["id"]})

    def _toggle_suppression(self) -> None:
        record = self.suppression_table.selected_record()
        if record:
            self.on_action(
                "suppression_toggle",
                {"id": record["id"], "enabled": not bool(record["enabled"])},
            )

    def _new_suppression(self) -> None:
        field = simpledialog.askstring(
            "Yeni susturma",
            "Alan (rule_id, process_name, executable_path, remote_ip, remote_port, local_port, username):",
            parent=self,
        )
        if not field:
            return
        allowed = {
            "rule_id",
            "process_name",
            "executable_path",
            "remote_ip",
            "remote_port",
            "local_port",
            "username",
        }
        if field not in allowed:
            messagebox.showerror("Susturma", "Desteklenmeyen alan.", parent=self)
            return
        value = simpledialog.askstring("Yeni susturma", "Eşit olacak değer:", parent=self)
        reason = simpledialog.askstring("Yeni susturma", "Neden:", parent=self)
        if not value or not reason:
            return
        if field in {"process_name", "username", "rule_id"} and not messagebox.askyesno(
            "Geniş kapsamlı susturma",
            "Bu koşul çok sayıda alarmı gizleyebilir. Devam edilsin mi?",
            parent=self,
        ):
            return
        self.on_action(
            "suppression_create",
            {
                "name": f"{field} = {value}",
                "conditions": {"field": field, "operator": "equals", "value": value},
                "reason": reason,
                "expires_at": None,
            },
        )

    def _delete_suppression(self) -> None:
        record = self.suppression_table.selected_record()
        if record and messagebox.askyesno(
            "Susturmayı sil",
            f"{record['name']} susturması silinsin mi? Eski alarmlar etkilenmez.",
            parent=self,
        ):
            self.on_action("suppression_delete", {"id": record["id"]})


def _combo(
    parent: ttk.Frame,
    values: tuple[str, ...],
    column: int,
    callback: Callable,
    default: str | None = None,
) -> ttk.Combobox:
    combo = ttk.Combobox(parent, values=values, state="readonly", width=14)
    combo.set(default if default in values else values[0])
    combo.grid(row=0, column=column, padx=3)
    combo.bind("<<ComboboxSelected>>", callback)
    return combo


def _text(parent: tk.Misc, height: int) -> tk.Text:
    return tk.Text(
        parent,
        height=height,
        wrap="word",
        background="#1e293b",
        foreground="#cbd5e1",
        relief="flat",
        font=("Segoe UI", 9),
    )


def _set_text(widget: tk.Text, value: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value)
    widget.configure(state="disabled")


def _rank(counter: Counter[str]) -> str:
    return "\n".join(
        f"{name or '—'}: {count}" for name, count in counter.most_common(8)
    ) or "Veri yok."


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _cutoff(label: str) -> datetime | None:
    seconds = {
        "Son 15 dakika": 900,
        "Last 15 Minutes": 900,
        "Son 1 saat": 3600,
        "Last 1 Hour": 3600,
        "Son 24 saat": 86400,
        "Last 24 Hours": 86400,
        "Son 7 gün": 604800,
        "Last 7 Days": 604800,
    }.get(label)
    return datetime.now(timezone.utc) - timedelta(seconds=seconds) if seconds else None


def _coverage_rows(
    rules: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in rules:
        if not rule.get("enabled"):
            continue
        for attack in rule.get("mitre_attack", []):
            tactics = f"{attack.get('tactic_id', '')} {attack.get('tactic_name', '')}".strip()
            technique = f"{attack.get('technique_id', '')} {attack.get('technique_name', '')}".strip()
            key = (tactics, technique)
            row = counts.setdefault(
                key,
                {
                    "_stable_key": f"{tactics}|{technique}",
                    "tactics_text": tactics or "—",
                    "techniques_text": technique or "—",
                    "enabled_rule_count": 0,
                    "count_24h": 0,
                    "total_count": 0,
                },
            )
            row["enabled_rule_count"] += 1
    for aggregate in alert_rows:
        tactics = ", ".join(json.loads(aggregate.get("mitre_tactics", "[]")))
        techniques = ", ".join(json.loads(aggregate.get("mitre_techniques", "[]")))
        key = (tactics, techniques)
        row = counts.setdefault(
            key,
            {
                "_stable_key": f"{tactics}|{techniques}",
                "tactics_text": tactics or "—",
                "techniques_text": techniques or "—",
                "enabled_rule_count": 0,
                "count_24h": 0,
                "total_count": 0,
            },
        )
        row["count_24h"] += int(aggregate.get("count_24h", 0))
        row["total_count"] += int(aggregate.get("total_count", 0))
    return list(counts.values())
