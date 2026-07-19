"""Tkinter Canvas line chart without an external plotting dependency."""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from math import ceil
from tkinter import ttk
from typing import Any


class HistoryChart(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        value_key: str,
        color: str,
        fixed_maximum: float | None = None,
    ) -> None:
        super().__init__(parent, style="Card.TFrame", padding=12)
        self.title = title
        self.value_key = value_key
        self.color = color
        self.fixed_maximum = fixed_maximum
        self._data: list[dict[str, Any]] = []

        ttk.Label(self, text=title, style="CardTitle.TLabel").pack(anchor="w")
        self.canvas = tk.Canvas(
            self,
            height=175,
            background="#1e293b",
            highlightthickness=0,
        )
        self.canvas.pack(fill="both", expand=True, pady=(8, 0))
        self.canvas.bind("<Configure>", self._redraw)

    def set_data(self, data: list[dict[str, Any]]) -> None:
        # Keep enough points for the display resolution instead of passing
        # hundreds of thousands of coordinates. Endpoints are always retained.
        maximum_points = 600
        if len(data) > maximum_points:
            step = ceil(len(data) / maximum_points)
            sampled = data[::step]
            if sampled[-1] is not data[-1]:
                sampled.append(data[-1])
            self._data = sampled
        else:
            self._data = data
        self._redraw()

    def _redraw(self, _event: tk.Event | None = None) -> None:
        canvas = self.canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 120)
        height = max(canvas.winfo_height(), 100)

        if not self._data:
            canvas.create_text(
                width / 2,
                height / 2,
                text="Bu zaman aralığında veri yok.",
                fill="#94a3b8",
                font=("Segoe UI", 10),
            )
            return

        left, top, right, bottom = 42, 12, width - 10, height - 28
        plot_width = max(right - left, 1)
        plot_height = max(bottom - top, 1)
        values = [float(item[self.value_key]) for item in self._data]
        maximum = self.fixed_maximum or max(max(values) * 1.1, 1.0)

        for index in range(5):
            y = top + (plot_height * index / 4)
            value = maximum * (1 - index / 4)
            canvas.create_line(left, y, right, y, fill="#334155")
            canvas.create_text(
                left - 6,
                y,
                text=f"{value:.0f}",
                anchor="e",
                fill="#64748b",
                font=("Segoe UI", 8),
            )

        point_count = len(values)
        points: list[float] = []
        for index, value in enumerate(values):
            x = left if point_count == 1 else left + plot_width * index / (point_count - 1)
            y = bottom - (min(max(value, 0.0), maximum) / maximum * plot_height)
            points.extend((x, y))

        if len(points) >= 4:
            canvas.create_line(*points, fill=self.color, width=2, smooth=True)
        else:
            canvas.create_oval(
                points[0] - 2,
                points[1] - 2,
                points[0] + 2,
                points[1] + 2,
                fill=self.color,
                outline=self.color,
            )

        first = _display_time(self._data[0]["timestamp"])
        last = _display_time(self._data[-1]["timestamp"])
        canvas.create_text(
            left, height - 10, text=first, anchor="w", fill="#64748b", font=("Segoe UI", 8)
        )
        canvas.create_text(
            right, height - 10, text=last, anchor="e", fill="#64748b", font=("Segoe UI", 8)
        )


def _display_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone()
        return parsed.strftime("%H:%M")
    except (TypeError, ValueError):
        return str(value)
