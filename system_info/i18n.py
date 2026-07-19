"""Thread-safe JSON localization, enum labels, and display formatting."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .settings import SUPPORTED_LANGUAGES

LOGGER = logging.getLogger(__name__)
DEFAULT_LOCALES_DIR = Path(__file__).resolve().parent.parent / "locales"


class LocaleLoadError(RuntimeError):
    """Raised when a locale resource is missing, malformed, or not an object."""


class I18n:
    """Provide fallback-safe translations and runtime language callbacks."""

    def __init__(
        self,
        language: str = "en",
        locales_dir: str | Path = DEFAULT_LOCALES_DIR,
    ) -> None:
        self.locales_dir = Path(locales_dir)
        self._lock = threading.RLock()
        self._callbacks: list[Callable[[str], None]] = []
        self._catalogs = {
            code: self._load_catalog(code) for code in SUPPORTED_LANGUAGES
        }
        self._validate_placeholders()
        self._language = language if language in SUPPORTED_LANGUAGES else "en"

    @property
    def language(self) -> str:
        with self._lock:
            return self._language

    def set_language(self, language: str) -> bool:
        if language not in SUPPORTED_LANGUAGES:
            language = "en"
        with self._lock:
            if language == self._language:
                return False
            self._language = language
            callbacks = tuple(self._callbacks)
        for callback in callbacks:
            try:
                callback(language)
            except Exception:
                LOGGER.exception("Language-change callback failed")
        return True

    def subscribe(self, callback: Callable[[str], None]) -> Callable[[], None]:
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._callbacks:
                    self._callbacks.remove(callback)

        return unsubscribe

    def t(self, key: str, **parameters: Any) -> str:
        with self._lock:
            language = self._language
            current = self._catalogs[language]
            english = self._catalogs["en"]
            template = current.get(key, english.get(key))
        if template is None:
            warning = f"[missing translation: {key}]"
            LOGGER.warning("Missing translation key: %s", key)
            return warning
        try:
            return template.format(**parameters)
        except (KeyError, IndexError, ValueError) as exc:
            LOGGER.warning("Translation formatting failed for %s: %s", key, exc)
            return template

    def has(self, key: str, language: str | None = None) -> bool:
        with self._lock:
            selected = language or self._language
            return key in self._catalogs[selected] or key in self._catalogs["en"]

    def optional(self, key: str, default: str, **parameters: Any) -> str:
        return self.t(key, **parameters) if self.has(key) else default

    def translate_literal(self, value: str, source_language: str = "tr") -> str:
        """Translate a legacy static literal by reverse-looking it up in a catalog."""
        with self._lock:
            source = self._catalogs.get(source_language, {})
            key = next(
                (
                    item_key
                    for item_key, item_value in source.items()
                    if item_value == value and "{" not in item_value
                ),
                None,
            )
        return self.t(key) if key else value

    def enum(self, domain: str, value: Any) -> str:
        code = canonical_enum(domain, value)
        return self.t(f"enums.{domain}.{code}")

    def _load_catalog(self, language: str) -> dict[str, str]:
        path = self.locales_dir / f"{language}.json"
        try:
            payload = _load_json_object(path)
        except (OSError, json.JSONDecodeError, UnicodeError) as exc:
            raise LocaleLoadError(f"Could not load locale {language}: {exc}") from exc
        if not isinstance(payload, dict):
            raise LocaleLoadError(f"Locale {language} must contain a JSON object")
        catalog = _flatten(payload)
        rule_path = self.locales_dir / "rules" / f"{language}.json"
        if rule_path.exists():
            try:
                rule_payload = _load_json_object(rule_path)
            except (OSError, json.JSONDecodeError, UnicodeError) as exc:
                raise LocaleLoadError(
                    f"Could not load rule locale {language}: {exc}"
                ) from exc
            if not isinstance(rule_payload, dict):
                raise LocaleLoadError(
                    f"Rule locale {language} must contain a JSON object"
                )
            catalog.update(_flatten({"rules": rule_payload}))
        if any(not value for value in catalog.values()):
            raise LocaleLoadError(f"Locale {language} contains an empty translation")
        return catalog

    def _validate_placeholders(self) -> None:
        english = self._catalogs["en"]
        for language, catalog in self._catalogs.items():
            for key in english.keys() & catalog.keys():
                if _placeholder_names(english[key]) != _placeholder_names(catalog[key]):
                    raise LocaleLoadError(
                        f"Placeholder mismatch for {key} in locale {language}"
                    )


def _flatten(payload: Mapping[str, Any], prefix: str = "") -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in payload.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            result.update(_flatten(value, full_key))
        elif isinstance(value, str):
            result[full_key] = value
        else:
            raise LocaleLoadError(f"Translation {full_key} must be a string")
    return result


def _load_json_object(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise LocaleLoadError(
                    f"Duplicate translation key {key!r} in {path.name}"
                )
            result[key] = value
        return result

    payload = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    if not isinstance(payload, dict):
        raise LocaleLoadError(f"Locale file {path.name} must contain an object")
    return payload


def _placeholder_names(value: str) -> set[str]:
    import string

    result: set[str] = set()
    for _literal, field, _format_spec, _conversion in string.Formatter().parse(value):
        if field:
            result.add(field.split(".", 1)[0].split("[", 1)[0])
    return result


ENUM_ALIASES: dict[str, dict[str, str]] = {
    "severity": {
        "bilgi": "info", "info": "info",
        "düşük": "low", "dusuk": "low", "low": "low",
        "orta": "medium", "medium": "medium",
        "yüksek": "high", "yuksek": "high", "high": "high",
        "kritik": "critical", "critical": "critical",
    },
    "alert_status": {
        "yeni": "new", "new": "new",
        "inceleniyor": "investigating", "investigating": "investigating",
        "doğrulandı": "confirmed", "dogrulandi": "confirmed", "confirmed": "confirmed",
        "yanlış pozitif": "false_positive", "yanlis pozitif": "false_positive",
        "false positive": "false_positive", "false_positive": "false_positive",
        "yoksayıldı": "ignored", "yoksayildi": "ignored", "ignored": "ignored",
        "kapatıldı": "closed", "kapatildi": "closed", "closed": "closed",
    },
    "case_status": {
        "açık": "open", "acik": "open", "open": "open",
        "inceleniyor": "investigating", "investigating": "investigating",
        "beklemede": "on_hold", "on hold": "on_hold", "on_hold": "on_hold",
        "çözüldü": "resolved", "cozuldu": "resolved", "resolved": "resolved",
        "yanlış pozitif": "false_positive", "false positive": "false_positive",
        "false_positive": "false_positive",
        "kapatıldı": "closed", "closed": "closed",
    },
    "finding_status": {
        "açık": "open", "open": "open",
        "incelendi": "reviewed", "reviewed": "reviewed",
        "yoksayıldı": "ignored", "ignored": "ignored",
    },
    "event_type": {
        "açıldı": "connection_opened", "connection opened": "connection_opened",
        "connection_opened": "connection_opened",
        "kapandı": "connection_closed", "connection closed": "connection_closed",
        "connection_closed": "connection_closed",
        "başladı": "process_started", "process started": "process_started",
        "process_started": "process_started",
        "process stopped": "process_stopped", "process_stopped": "process_stopped",
        "dinleme başladı": "listener_started", "listening started": "listener_started",
        "listener_started": "listener_started",
        "dinleme sona erdi": "listener_stopped", "listening stopped": "listener_stopped",
        "listener_stopped": "listener_stopped",
        "bağlantı açıldı": "connection_opened",
        "bağlantı kapandı": "connection_closed",
        "yeni uzak hedef": "remote_endpoint_new",
        "new remote endpoint": "remote_endpoint_new",
        "remote_endpoint_new": "remote_endpoint_new",
        "uzak hedef yeniden görüldü": "remote_endpoint_reappeared",
        "remote endpoint reappeared": "remote_endpoint_reappeared",
        "remote_endpoint_reappeared": "remote_endpoint_reappeared",
        "network_finding": "network_finding",
    },
    "process_event": {
        "başladı": "process_started", "process started": "process_started",
        "process_started": "process_started",
        "kapandı": "process_stopped", "process stopped": "process_stopped",
        "process_stopped": "process_stopped",
    },
    "connection_event": {
        "açıldı": "connection_opened", "connection opened": "connection_opened",
        "connection_opened": "connection_opened",
        "kapandı": "connection_closed", "connection closed": "connection_closed",
        "connection_closed": "connection_closed",
    },
    "listener_event": {
        "dinleme başladı": "listener_started", "listening started": "listener_started",
        "listener_started": "listener_started",
        "dinleme sona erdi": "listener_stopped", "listening stopped": "listener_stopped",
        "listener_stopped": "listener_stopped",
    },
    "network_event": {
        "bağlantı açıldı": "connection_opened", "connection opened": "connection_opened",
        "connection_opened": "connection_opened",
        "bağlantı kapandı": "connection_closed", "connection closed": "connection_closed",
        "connection_closed": "connection_closed",
        "dinleme başladı": "listener_started", "listening started": "listener_started",
        "listener_started": "listener_started",
        "dinleme sona erdi": "listener_stopped", "listening stopped": "listener_stopped",
        "listener_stopped": "listener_stopped",
        "yeni uzak hedef": "remote_endpoint_new",
        "new remote endpoint": "remote_endpoint_new",
        "remote_endpoint_new": "remote_endpoint_new",
        "uzak hedef yeniden görüldü": "remote_endpoint_reappeared",
        "remote endpoint reappeared": "remote_endpoint_reappeared",
        "remote_endpoint_reappeared": "remote_endpoint_reappeared",
        "baseline": "baseline",
        "görüldü": "seen", "seen": "seen",
    },
    "address_scope": {
        "loopback": "loopback",
        "yalnızca yerel cihaz": "local_device", "local device only": "local_device",
        "local_device": "local_device",
        "özel ağ": "private", "private network": "private", "private": "private",
        "link-local": "link_local", "link_local": "link_local",
        "tüm arayüzler": "all_interfaces", "all interfaces": "all_interfaces",
        "all_interfaces": "all_interfaces",
        "genel / public": "public", "public": "public",
        "belirsiz": "uncertain", "uncertain": "uncertain",
    },
    "network_status": {
        "bağlı": "connected", "connected": "connected",
        "dinliyor": "listening", "listening": "listening",
        "established": "established", "listen": "listening",
        "none": "none", "syn_sent": "syn_sent", "syn_recv": "syn_recv",
        "fin_wait1": "fin_wait1", "fin_wait2": "fin_wait2",
        "time_wait": "time_wait", "close": "closed",
        "closed": "closed", "close_wait": "close_wait",
        "last_ack": "last_ack", "closing": "closing",
        "delete_tcb": "delete_tcb", "idle": "idle", "bound": "bound",
    },
}


def canonical_enum(domain: str, value: Any) -> str:
    text = str(value or "").strip()
    normalized = text.casefold().replace("\u0307", "")
    return ENUM_ALIASES.get(domain, {}).get(normalized, text or "unknown")


_default_lock = threading.Lock()
_default_i18n: I18n | None = None


def get_i18n() -> I18n:
    global _default_i18n
    with _default_lock:
        if _default_i18n is None:
            _default_i18n = I18n("en")
        return _default_i18n


def configure_i18n(language: str, locales_dir: str | Path = DEFAULT_LOCALES_DIR) -> I18n:
    global _default_i18n
    with _default_lock:
        _default_i18n = I18n(language, locales_dir)
        return _default_i18n


def t(key: str, **parameters: Any) -> str:
    return get_i18n().t(key, **parameters)


def format_datetime(value: datetime | str | None, language: str | None = None) -> str:
    if value in {None, ""}:
        return "—"
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        parsed = value
    selected = language or get_i18n().language
    return parsed.strftime("%d.%m.%Y %H:%M:%S" if selected == "tr" else "%Y-%m-%d %H:%M:%S")


def format_number(value: float | int, decimals: int = 1, language: str | None = None) -> str:
    rendered = f"{float(value):.{decimals}f}"
    return rendered.replace(".", ",") if (language or get_i18n().language) == "tr" else rendered


def localize_widget_tree(root: Any, i18n: I18n | None = None) -> None:
    """Translate legacy static Tk widget labels, tabs, headings, and options."""
    import tkinter as tk
    from tkinter import ttk

    translator = i18n or get_i18n()

    def translate(value: Any) -> str:
        return translator.translate_literal(str(value))

    def walk(widget: Any) -> None:
        try:
            current = widget.cget("text")
            if current:
                widget.configure(text=translate(current))
        except (tk.TclError, KeyError):
            pass
        if isinstance(widget, ttk.Combobox):
            values = tuple(translate(value) for value in widget.cget("values"))
            widget.configure(values=values)
            current = str(widget.get())
            translated = translate(current)
            if translated != current:
                widget.set(translated)
        if isinstance(widget, ttk.Notebook):
            for tab_id in widget.tabs():
                widget.tab(tab_id, text=translate(widget.tab(tab_id, "text")))
        if isinstance(widget, ttk.Treeview):
            for column in widget.cget("columns"):
                heading = widget.heading(column, "text")
                widget.heading(column, text=translate(heading))
            if widget.heading("#0", "text"):
                widget.heading("#0", text=translate(widget.heading("#0", "text")))
        for child in widget.winfo_children():
            walk(child)

    walk(root)
