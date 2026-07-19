"""Safe access to bundled UI assets."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from typing import Any

FLAGS_DIRECTORY = Path(__file__).resolve().parent.parent / "assets" / "flags"
FLAG_FILENAMES = {"tr": "tr.png", "en": "gb.png"}
FLAG_FALLBACK_TEXT = {"tr": "TR", "en": "EN"}


def load_flag_image(
    language: str,
    *,
    loader: Callable[..., Any] = tk.PhotoImage,
) -> tuple[Any | None, str]:
    """Return a bundled flag image or accessible text when loading fails."""
    filename = FLAG_FILENAMES.get(language)
    fallback = FLAG_FALLBACK_TEXT.get(language, language.upper())
    if filename is None:
        return None, fallback
    try:
        return loader(file=FLAGS_DIRECTORY / filename), ""
    except (OSError, tk.TclError):
        return None, fallback

