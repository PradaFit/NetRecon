"""Reusable GUI widgets"""

import tkinter as tk
import customtkinter as ctk
from .theme import COLORS, FONT_FAMILY, FONT_MONO


class OutputConsole(ctk.CTkTextbox):
    """Scrollable, read-only text widget for displaying results."""

    def __init__(self, master, **kwargs):
        defaults = {
            "font": (FONT_MONO, 13),
            "fg_color": COLORS["bg_dark"],
            "text_color": COLORS["text"],
            "corner_radius": 8,
            "border_width": 1,
            "border_color": COLORS["border"],
            "wrap": "word",
        }
        defaults.update(kwargs)
        super().__init__(master, **defaults)
        self.configure(state="disabled")

        # Tag colors for the underlying tk.Text
        self._text = self._textbox
        self._text.tag_config("info", foreground=COLORS["accent"])
        self._text.tag_config("success", foreground=COLORS["success"])
        self._text.tag_config("warning", foreground=COLORS["warning"])
        self._text.tag_config("error", foreground=COLORS["error"])
        self._text.tag_config("dim", foreground=COLORS["text_dim"])
        self._text.tag_config("bold", font=(FONT_MONO, 13, "bold"))
        self._text.tag_config(
            "header", foreground=COLORS["accent"], font=(FONT_MONO, 14, "bold")
        )

    def append(self, text, tag=None):
        self.configure(state="normal")
        if tag:
            self._text.insert("end", text, tag)
        else:
            self._text.insert("end", text)
        self.configure(state="disabled")
        self.see("end")

    def append_line(self, text, tag=None):
        self.append(text + "\n", tag)

    def clear(self):
        self.configure(state="normal")
        self._text.delete("1.0", "end")
        self.configure(state="disabled")

    def get_text(self):
        return self._text.get("1.0", "end-1c")


class StatusBar(ctk.CTkFrame):
    """Bottom status bar with message and indicator."""

    def __init__(self, master, **kwargs):
        super().__init__(
            master, height=30, corner_radius=0, fg_color=COLORS["bg_sidebar"], **kwargs
        )
        self.pack_propagate(False)
        self._label = ctk.CTkLabel(
            self,
            text="Ready",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._label.pack(side="left", padx=12, fill="x", expand=True)

        self._right = ctk.CTkLabel(
            self,
            text="",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_dim"],
            anchor="e",
        )
        self._right.pack(side="right", padx=12)

    def set_message(self, text, level="info"):
        color_map = {
            "info": COLORS["text_dim"],
            "success": COLORS["success"],
            "warning": COLORS["warning"],
            "error": COLORS["error"],
        }
        self._label.configure(
            text=text, text_color=color_map.get(level, COLORS["text_dim"])
        )

    def set_right(self, text):
        self._right.configure(text=text)


class ExportBar(ctk.CTkFrame):
    """Row of export/action buttons at bottom of a tab."""

    def __init__(
        self,
        master,
        on_json=None,
        on_csv=None,
        on_html=None,
        on_copy=None,
        on_clear=None,
        on_map=None,
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)

        btn_cfg = {
            "height": 30,
            "corner_radius": 6,
            "font": (FONT_FAMILY, 12),
            "fg_color": COLORS["bg_input"],
            "hover_color": COLORS["accent_dim"],
            "text_color": COLORS["text"],
            "border_width": 1,
            "border_color": COLORS["border"],
        }

        actions = [
            ("Export JSON", on_json),
            ("Export CSV", on_csv),
            ("Export HTML", on_html),
        ]
        if on_map:
            actions.append(("Generate Map", on_map))
        actions.extend(
            [
                ("Copy", on_copy),
                ("Clear", on_clear),
            ]
        )

        for text, cmd in actions:
            if cmd:
                btn = ctk.CTkButton(self, text=text, command=cmd, width=100, **btn_cfg)
                btn.pack(side="left", padx=(0, 6), pady=4)


class LabeledEntry(ctk.CTkFrame):
    """Input field with a label above it."""

    def __init__(self, master, label, placeholder="", width=220, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        ctk.CTkLabel(
            self,
            text=label,
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).pack(anchor="w")

        self.entry = ctk.CTkEntry(
            self,
            width=width,
            height=34,
            placeholder_text=placeholder,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            corner_radius=6,
        )
        self.entry.pack(fill="x")

    def get(self):
        return self.entry.get().strip()

    def set(self, value):
        self.entry.delete(0, "end")
        self.entry.insert(0, value)

    def clear(self):
        self.entry.delete(0, "end")


class LabeledDropdown(ctk.CTkFrame):
    """Dropdown with a label above it."""

    def __init__(
        self, master, label, values, default=None, width=200, command=None, **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)

        ctk.CTkLabel(
            self,
            text=label,
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).pack(anchor="w")

        self.var = ctk.StringVar(value=default or (values[0] if values else ""))
        self.dropdown = ctk.CTkOptionMenu(
            self,
            values=values,
            variable=self.var,
            width=width,
            height=34,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["bg_input"],
            button_color=COLORS["accent_dim"],
            button_hover_color=COLORS["accent_hover"],
            text_color=COLORS["text"],
            dropdown_fg_color=COLORS["bg_card"],
            dropdown_text_color=COLORS["text"],
            dropdown_hover_color=COLORS["accent_dim"],
            corner_radius=6,
            command=command,
        )
        self.dropdown.pack(fill="x")

    def get(self):
        return self.var.get()

    def set(self, value):
        self.var.set(value)
