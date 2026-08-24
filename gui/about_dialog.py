"""
About / Support window for NetRecon.

Includes version info, project links, the disclaimer text, and a
"Support Development" button. No telemetry, no tracking, no popups
outside of this window.
"""

import sys
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from netrecon import __version__, __author__
from netrecon import logger as nr_logger
from .theme import COLORS, FONT_FAMILY, FONT_MONO
from .windowing import apply_window_icon


GITHUB_URL = "https://github.com/PradaFit/NetRecon"
ISSUES_URL = "https://github.com/PradaFit/NetRecon/issues"
SUPPORT_URL = "https://github.com/PradaFit/NetRecon"
PRIVACY_URL = "https://github.com/PradaFit/NetRecon/blob/main/PRIVACY.md"
log = nr_logger.get_logger("gui.about")


def _find_bundled(filename: str) -> Path | None:
    """Locate a bundled doc next to the installed app or in source."""
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / filename)
    candidates.extend(
        [
            Path(__file__).resolve().parent.parent / filename,
            Path(sys.executable).resolve().parent / filename,
            Path.cwd() / filename,
        ]
    )
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def _read_disclaimer() -> str:
    """Look up DISCLAIMER.md alongside the installed app."""
    path = _find_bundled("DISCLAIMER.md")
    if path:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            pass
    return (
        "NetRecon is provided for lawful security testing and authorized "
        "network diagnostics. Use it only on systems you own or have "
        "explicit permission to assess."
    )


class AboutDialog(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("About NetRecon")
        self._window_icon_path = apply_window_icon(self)
        self.geometry("620x540")
        self.minsize(560, 480)
        self.configure(fg_color=COLORS["bg_dark"])
        self.transient(parent)

        self._build_header()
        self._build_tabs()
        self._build_footer()
        self.after(40, lambda: self._center(parent))

    def _center(self, parent):
        try:
            self.update_idletasks()
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            w = self.winfo_width()
            h = self.winfo_height()
            self.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")
        except Exception as exc:
            log.debug("Could not center About window: %s", type(exc).__name__)

    def _build_header(self):
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", padx=20, pady=(18, 8))

        ctk.CTkLabel(
            head,
            text="NetRecon",
            font=(FONT_FAMILY, 22, "bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            head,
            text=f"Version {__version__}  |  Developed by {__author__}Dev",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            head,
            text="Open source under GPLv3.",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w", pady=(2, 0))

    def _build_tabs(self):
        tabs = ctk.CTkTabview(
            self,
            fg_color=COLORS["bg_dark"],
            segmented_button_fg_color=COLORS["bg_sidebar"],
            segmented_button_selected_color=COLORS["accent_dim"],
            segmented_button_selected_hover_color=COLORS["accent_hover"],
            segmented_button_unselected_color=COLORS["bg_sidebar"],
            segmented_button_unselected_hover_color=COLORS["bg_input"],
            text_color=COLORS["text"],
            corner_radius=8,
        )
        tabs.pack(fill="both", expand=True, padx=20, pady=(4, 10))

        info_frame = tabs.add("  Info  ")
        disc_frame = tabs.add("  Responsible Use  ")
        diag_frame = tabs.add("  Diagnostics  ")

        self._build_info_tab(info_frame)
        self._build_disclaimer_tab(disc_frame)
        self._build_diagnostics_tab(diag_frame)

    def _build_info_tab(self, frame):
        wrap = ctk.CTkFrame(frame, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=4, pady=8)

        info = (
            "NetRecon is a desktop and command-line toolkit for DNS lookups, "
            "native async TCP port scanning, optional Nmap-driven enumeration, "
            "IP geolocation, and exportable scan history."
        )
        ctk.CTkLabel(
            wrap,
            text=info,
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text"],
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        self._link_button(wrap, "GitHub Repository", GITHUB_URL)
        self._link_button(wrap, "Report an Issue", ISSUES_URL)
        ctk.CTkButton(
            wrap,
            text="Privacy Policy",
            command=self._open_privacy,
            width=240,
            height=32,
            anchor="w",
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["bg_card"],
            text_color=COLORS["text"],
            font=(FONT_FAMILY, 12),
        ).pack(anchor="w", pady=4)
        self._link_button(
            wrap,
            "Support Development",
            SUPPORT_URL,
            accent=True,
        )

    def _build_disclaimer_tab(self, frame):
        box = ctk.CTkTextbox(
            frame,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=8,
            wrap="word",
            font=(FONT_FAMILY, 12),
        )
        box.pack(fill="both", expand=True, padx=4, pady=8)
        box.insert("1.0", _read_disclaimer())
        box.configure(state="disabled")

    def _build_diagnostics_tab(self, frame):
        wrap = ctk.CTkFrame(frame, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=4, pady=8)

        ctk.CTkLabel(
            wrap,
            text=(
                "Diagnostic logs help troubleshoot issues when filing a bug "
                "report. Exported logs are sanitized: home directory paths, "
                "IP addresses, and email addresses are redacted."
            ),
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text"],
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            wrap,
            text="Log location: ~/.netrecon/logs/netrecon.log",
            font=(FONT_MONO, 11),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w", pady=(0, 12))

        ctk.CTkButton(
            wrap,
            text="Export Diagnostic Log",
            command=self._export_log,
            width=200,
            height=34,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["text_bright"],
            font=(FONT_FAMILY, 12, "bold"),
        ).pack(anchor="w")

    def _build_footer(self):
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=20, pady=(0, 16))

        ctk.CTkButton(
            footer,
            text="Close",
            command=self.destroy,
            width=100,
            height=32,
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["bg_card"],
            text_color=COLORS["text"],
            font=(FONT_FAMILY, 12),
        ).pack(side="right")

    def _link_button(self, parent, label, url, accent=False):
        ctk.CTkButton(
            parent,
            text=label,
            command=lambda u=url: self._open_url(u),
            width=240,
            height=32,
            anchor="w",
            fg_color=COLORS["accent_dim"] if accent else COLORS["bg_input"],
            hover_color=COLORS["accent_hover"] if accent else COLORS["bg_card"],
            text_color=COLORS["text_bright"] if accent else COLORS["text"],
            font=(FONT_FAMILY, 12, "bold" if accent else "normal"),
        ).pack(anchor="w", pady=4)

    def _open_url(self, url):
        try:
            if not webbrowser.open_new_tab(url):
                raise RuntimeError("No default browser accepted the URL")
        except Exception:
            messagebox.showerror("NetRecon", f"Could not open browser:\n{url}")

    def _open_privacy(self):
        local = _find_bundled("PRIVACY.md")
        if local:
            try:
                if webbrowser.open_new_tab(local.as_uri()):
                    return
            except Exception as exc:
                log.debug("Could not open local privacy file: %s", type(exc).__name__)
        self._open_url(PRIVACY_URL)

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export Diagnostic Log",
            defaultextension=".txt",
            initialfile="netrecon-diagnostic.txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        ok = nr_logger.export_diagnostic_log(path)
        if ok:
            messagebox.showinfo("NetRecon", f"Diagnostic log saved to:\n{path}")
        else:
            messagebox.showerror(
                "NetRecon", "Could not write diagnostic log to that location."
            )
