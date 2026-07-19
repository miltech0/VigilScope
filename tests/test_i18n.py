from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from system_info.i18n import I18n, LocaleLoadError, format_datetime
from system_info.rule_loader import localized_builtin_rule


def test_turkish_and_english_locales_have_equal_keys() -> None:
    i18n = I18n("tr")
    assert i18n.t("tabs.processes") == "İşlemler"
    turkish_keys = set(i18n._catalogs["tr"])
    english_keys = set(i18n._catalogs["en"])
    assert turkish_keys == english_keys


def test_missing_key_falls_back_to_english(tmp_path: Path) -> None:
    (tmp_path / "en.json").write_text(
        json.dumps({"only": {"english": "Fallback"}, "greeting": "Hello {name}"}),
        encoding="utf-8",
    )
    (tmp_path / "tr.json").write_text(
        json.dumps({"greeting": "Merhaba {name}"}),
        encoding="utf-8",
    )
    i18n = I18n("tr", tmp_path)
    assert i18n.t("only.english") == "Fallback"
    assert i18n.t("missing.key") == "[missing translation: missing.key]"


def test_parameters_and_missing_parameters_are_safe() -> None:
    i18n = I18n("tr")
    assert i18n.t("dashboard.active_connections", count=42) == "42 aktif bağlantı"
    assert "{count}" in i18n.t("dashboard.active_connections")
    i18n.set_language("en")
    assert i18n.t("dashboard.active_connections", count=42) == "42 active connections"


def test_malformed_locale_json_is_controlled(tmp_path: Path) -> None:
    (tmp_path / "en.json").write_text("{", encoding="utf-8")
    (tmp_path / "tr.json").write_text("{}", encoding="utf-8")
    with pytest.raises(LocaleLoadError):
        I18n("en", tmp_path)


def test_duplicate_locale_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "en.json").write_text(
        '{"duplicate":"one","duplicate":"two"}',
        encoding="utf-8",
    )
    (tmp_path / "tr.json").write_text('{"duplicate":"bir"}', encoding="utf-8")
    with pytest.raises(LocaleLoadError):
        I18n("en", tmp_path)


def test_unknown_language_falls_back_and_callbacks_run() -> None:
    i18n = I18n("unknown")
    observed: list[str] = []
    unsubscribe = i18n.subscribe(observed.append)
    assert i18n.language == "en"
    assert i18n.set_language("tr")
    assert observed == ["tr"]
    unsubscribe()
    i18n.set_language("en")
    assert observed == ["tr"]


def test_language_specific_date_formatting() -> None:
    value = datetime(2026, 7, 19, 14, 35, 20)
    assert format_datetime(value, "tr") == "19.07.2026 14:35:20"
    assert format_datetime(value, "en") == "2026-07-19 14:35:20"


def test_builtin_rule_display_is_localized() -> None:
    tr = I18n("tr")
    en = I18n("en")
    assert "Office uygulaması" in tr.t("rules.PROC-001.title")
    assert "Office application" in en.t("rules.PROC-001.title")


def test_user_rule_text_is_not_translated() -> None:
    user_rule = {
        "id": "USER-001",
        "title": "Benim kuralım",
        "description": "Kullanıcı metni",
        "category": "Özel",
    }
    assert localized_builtin_rule(user_rule, I18n("en")) == user_rule
