"""UTF-8 application settings with safe defaults and atomic writes."""

from __future__ import annotations

import json
import locale
import os
import tempfile
from pathlib import Path
from typing import Callable

from .product import SETTINGS_FILENAME
from .filesystem_security import ensure_private_directory, ensure_private_file

SUPPORTED_LANGUAGES = ("tr", "en")


def detect_system_language(detector: Callable[[], str | None] | None = None) -> str:
    """Return Turkish for a Turkish Windows UI and English otherwise."""
    try:
        language = (detector or _system_locale)() or ""
    except Exception:
        language = ""
    return "tr" if language.casefold().startswith("tr") else "en"


def _system_locale() -> str | None:
    if os.name == "nt":
        try:
            import ctypes

            language_id = int(
                ctypes.windll.kernel32.GetUserDefaultUILanguage()
            )
            windows_name = locale.windows_locale.get(language_id)
            if windows_name:
                return windows_name
        except (AttributeError, OSError, ValueError):
            pass
    language, _encoding = locale.getlocale()
    return language


class SettingsStore:
    """Read and atomically persist user preferences without raising on corruption."""

    def __init__(
        self,
        data_dir: str | Path,
        system_language_detector: Callable[[], str | None] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / SETTINGS_FILENAME
        self._system_language_detector = system_language_detector

    def load(self) -> dict[str, str]:
        default = {
            "language": detect_system_language(self._system_language_detector)
        }
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return default
        if not isinstance(payload, dict):
            return default
        language = str(payload.get("language", "")).casefold()
        if language not in SUPPORTED_LANGUAGES:
            language = default["language"]
        return {"language": language}

    def save_language(self, language: str) -> None:
        language = language.casefold()
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language code: {language}")
        ensure_private_directory(self.data_dir)
        payload = json.dumps(
            {"language": language},
            ensure_ascii=False,
            indent=2,
        ) + "\n"
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{SETTINGS_FILENAME}.",
            suffix=".tmp",
            dir=self.data_dir,
            text=True,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
            ensure_private_file(self.path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
