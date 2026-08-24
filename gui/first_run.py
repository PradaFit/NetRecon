"""
First-run responsible-use notice.

Shown once after install (and once after every major version bump).
Acceptance is persisted to the user's NetRecon preferences file so the
dialog does not appear on every launch.
"""

import tkinter as tk
import customtkinter as ctk

from netrecon import preferences, __version__
from netrecon import logger as nr_logger
from .theme import COLORS, FONT_FAMILY


log = nr_logger.get_logger("gui.first_run")

NOTICE_TEXT = (
    "NetRecon is a network diagnostics and authorized security testing toolkit.\n\n"
    "Use it only on systems, networks, and domains that you own or that you have "
    "explicit written permission to assess. Scanning third-party infrastructure "
    "without authorization may violate local, national, or international law and "
    "the acceptable-use policies of your network or internet provider.\n\n"
    "You are responsible for how you use this software."
)

CONFIRM_LABEL = (
    "I understand NetRecon is for authorized network diagnostics and security testing."
)


def needs_acceptance() -> bool:
    return not preferences.is_responsible_use_accepted(__version__)


class ResponsibleUseDialog(ctk.CTkToplevel):
    """Modal first-run notice. Closes the app if the user declines."""

    def __init__(self, parent):
        super().__init__(parent)
        self._parent = parent
        self._accepted = False

        self.title("NetRecon: Responsible Use")
        self.geometry("560x360")
        self.minsize(520, 340)
        self.configure(fg_color=COLORS["bg_dark"])
        self.resizable(False, False)

        # Modal behaviour
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_decline)

        ctk.CTkLabel(
            self,
            text="Responsible Use Notice",
            font=(FONT_FAMILY, 16, "bold"),
            text_color=COLORS["text_bright"],
        ).pack(pady=(18, 6), padx=20, anchor="w")

        body = ctk.CTkTextbox(
            self,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=8,
            wrap="word",
            font=(FONT_FAMILY, 12),
            height=160,
        )
        body.pack(fill="x", padx=20, pady=(0, 12))
        body.insert("1.0", NOTICE_TEXT)
        body.configure(state="disabled")

        self._agree_var = tk.BooleanVar(value=False)
        self._checkbox = ctk.CTkCheckBox(
            self,
            text=CONFIRM_LABEL,
            variable=self._agree_var,
            command=self._on_toggle,
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text"],
            checkbox_width=18,
            checkbox_height=18,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
        )
        self._checkbox.pack(padx=20, pady=(0, 12), anchor="w")

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(0, 18))

        self._continue_btn = ctk.CTkButton(
            btn_row,
            text="Continue",
            command=self._on_accept,
            width=120,
            height=34,
            state="disabled",
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["text_bright"],
            font=(FONT_FAMILY, 12, "bold"),
        )
        self._continue_btn.pack(side="right")

        ctk.CTkButton(
            btn_row,
            text="Exit NetRecon",
            command=self._on_decline,
            width=120,
            height=34,
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["bg_card"],
            text_color=COLORS["text"],
            font=(FONT_FAMILY, 12),
        ).pack(side="right", padx=(0, 8))

        # Center over parent
        self.after(50, self._center_on_parent)

    def _center_on_parent(self):
        try:
            self.update_idletasks()
            px = self._parent.winfo_rootx()
            py = self._parent.winfo_rooty()
            pw = self._parent.winfo_width()
            ph = self._parent.winfo_height()
            w = self.winfo_width()
            h = self.winfo_height()
            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except Exception as exc:
            log.debug("Could not center responsible-use window: %s", type(exc).__name__)

    def _on_toggle(self):
        if self._agree_var.get():
            self._continue_btn.configure(state="normal")
        else:
            self._continue_btn.configure(state="disabled")

    def _on_accept(self):
        preferences.accept_responsible_use(__version__)
        self._accepted = True
        self.grab_release()
        self.destroy()

    def _on_decline(self):
        self._accepted = False
        self.grab_release()
        self.destroy()

    @property
    def accepted(self) -> bool:
        return self._accepted


def prompt_if_needed(parent) -> bool:
    """
    Show the notice if it has not been accepted yet.
    Returns True if the application may continue, False if it should exit.
    """
    if not needs_acceptance():
        return True
    dlg = ResponsibleUseDialog(parent)
    parent.wait_window(dlg)
    return dlg.accepted
