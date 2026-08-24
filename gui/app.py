"""Main application window for NetRecon."""

import sys
import customtkinter as ctk

from .theme import COLORS, FONT_FAMILY, FONT_MONO
from .widgets import StatusBar
from .first_run import prompt_if_needed
from .about_dialog import AboutDialog
from .windowing import (
    apply_window_icon,
    center_mapped_window,
    center_window,
    current_window_center,
)
from netrecon import __version__, preferences
from netrecon.db_manager import DatabaseManager
from netrecon import logger as nr_logger
from netrecon.platform_utils import platform_info


log = nr_logger.get_logger("gui")

PRADAFIT_LOGO = (
    " ________              _________      ___________________\n"
    " ___  __ \\____________ ______  /_____ ___  ____/__(_)_  /_\n"
    " __  /_/ /_  ___/  __ `/  __  /_  __ `/_  /_   __  /_  __/\n"
    " _  ____/_  /   / /_/ // /_/ / / /_/ /_  __/   _  / / /_\n"
    " /_/     /_/    \\__,_/ \\__,_/  \\__,_/ /_/      /_/  \\__/"
)

WINDOW_WIDTH = 1300
WINDOW_HEIGHT = 860


class PradaFitApp(ctk.CTk):
    """Primary window with tabbed interface."""

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(
            f"NetRecon v{__version__}: Network Reconnaissance Toolkit  |  by PradaFit"
        )
        self.minsize(960, 600)

        self._window_icon_path = apply_window_icon(self)
        if self._window_icon_path is None:
            log.debug("Could not apply the NetRecon window icon")

        self.configure(fg_color=COLORS["bg_dark"])

        # Shared db
        self.db = DatabaseManager()
        self._about_dialog = None
        self._dns_tab = None
        self._scan_tab = None
        self._geo_tab = None
        self._hist_tab = None
        self._tab_frames = {}

        self._build_ui()
        self._monitor_anchor = preferences.get_window_anchor()
        self._initial_placement = center_window(
            self,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            anchor=self._monitor_anchor,
        )
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        header = ctk.CTkFrame(
            self, fg_color=COLORS["bg_sidebar"], height=100, corner_radius=0
        )
        header.pack(fill="x")
        header.pack_propagate(False)

        logo_label = ctk.CTkLabel(
            header,
            text=PRADAFIT_LOGO,
            font=(FONT_MONO, 9),
            text_color=COLORS["accent"],
            justify="left",
        )
        logo_label.pack(side="left", padx=16, pady=4)

        # Right side info block
        info_frame = ctk.CTkFrame(header, fg_color="transparent")
        info_frame.pack(side="right", padx=16, pady=8)

        ctk.CTkLabel(
            info_frame,
            text=f"v{__version__}",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_dim"],
        ).pack(anchor="e")

        admin_text = "Admin" if platform_info.is_admin else "Standard"
        nmap_text = "Nmap OK" if platform_info.find_nmap() else "Nmap N/A"
        plat = f"{platform_info.system.title()} {platform_info.release} | {admin_text} | {nmap_text}"
        ctk.CTkLabel(
            info_frame,
            text=plat,
            font=(FONT_FAMILY, 10),
            text_color=COLORS["text_dim"],
        ).pack(anchor="e")

        ctk.CTkLabel(
            info_frame,
            text="Native TCP Scanner Ready",
            font=(FONT_FAMILY, 10),
            text_color=COLORS["success"],
        ).pack(anchor="e")

        ctk.CTkButton(
            info_frame,
            text="About",
            command=self._open_about,
            width=80,
            height=24,
            corner_radius=6,
            font=(FONT_FAMILY, 11),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["accent_dim"],
            text_color=COLORS["text"],
            border_width=1,
            border_color=COLORS["border"],
        ).pack(anchor="e", pady=(4, 0))

        # status bar (bottom) 
        self.status_bar = StatusBar(self)
        self.status_bar.pack(side="bottom", fill="x")
        self.status_bar.set_right(
            f"Python {sys.version_info.major}.{sys.version_info.minor}"
        )

        self.tabview = ctk.CTkTabview(
            self,
            fg_color=COLORS["bg_dark"],
            segmented_button_fg_color=COLORS["bg_sidebar"],
            segmented_button_selected_color=COLORS["accent_dim"],
            segmented_button_selected_hover_color=COLORS["accent_hover"],
            segmented_button_unselected_color=COLORS["bg_sidebar"],
            segmented_button_unselected_hover_color=COLORS["bg_input"],
            text_color=COLORS["text"],
            corner_radius=8,
            command=self._on_tab_change,
        )
        self.tabview.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        for name in ("DNS Lookup", "Port Scanner", "Geolocation", "History"):
            self._tab_frames[name] = self.tabview.add(f"  {name}  ")

        self.tabview.set("  DNS Lookup  ")

    def _ensure_tab(self, name):
        """Build a tab on first use so the main window can render promptly."""
        if name == "DNS Lookup" and self._dns_tab is None:
            from .dns_tab import DNSTab

            self._dns_tab = DNSTab(
                self._tab_frames[name], status_bar=self.status_bar, db=self.db
            )
            self._dns_tab.pack(fill="both", expand=True)
        elif name == "Port Scanner" and self._scan_tab is None:
            from .scan_tab import ScanTab

            self._scan_tab = ScanTab(
                self._tab_frames[name], status_bar=self.status_bar, db=self.db
            )
            self._scan_tab.pack(fill="both", expand=True)
        elif name == "Geolocation" and self._geo_tab is None:
            from .geo_tab import GeoTab

            self._geo_tab = GeoTab(
                self._tab_frames[name], status_bar=self.status_bar, db=self.db
            )
            self._geo_tab.pack(fill="both", expand=True)
        elif name == "History" and self._hist_tab is None:
            from .history_tab import HistoryTab

            self._hist_tab = HistoryTab(
                self._tab_frames[name], status_bar=self.status_bar, db=self.db
            )
            self._hist_tab.pack(fill="both", expand=True)

    def initialize_default_tab(self):
        self._ensure_tab("DNS Lookup")

    @property
    def dns_tab(self):
        self._ensure_tab("DNS Lookup")
        return self._dns_tab

    @property
    def scan_tab(self):
        self._ensure_tab("Port Scanner")
        return self._scan_tab

    @property
    def geo_tab(self):
        self._ensure_tab("Geolocation")
        return self._geo_tab

    @property
    def hist_tab(self):
        self._ensure_tab("History")
        return self._hist_tab

    def _open_about(self):
        if self._about_dialog is not None:
            try:
                if self._about_dialog.winfo_exists():
                    self._about_dialog.focus_force()
                    return
            except Exception as exc:
                log.debug("About window state check failed: %s", type(exc).__name__)
                self._about_dialog = None
        self._about_dialog = AboutDialog(self)

    def _on_close(self):
        anchor = current_window_center(self)
        if anchor is not None and not preferences.save_window_anchor(*anchor):
            log.debug("Could not save the main-window monitor anchor")
        if self._scan_tab is not None:
            self._scan_tab.shutdown()
        self.destroy()

    def _on_tab_change(self):
        try:
            name = self.tabview.get()
        except Exception as exc:
            log.warning("Could not read selected tab: %s", type(exc).__name__)
            return
        selected = name.strip()
        self._ensure_tab(selected)
        if selected == "History":
            try:
                self.hist_tab._refresh()
            except Exception:
                log.exception("History refresh failed")


def launch_gui():
    """Fire up the GUI."""
    log.info("NetRecon GUI starting (v%s)", __version__)
    try:
        app = PradaFitApp()
        # Render the main window once so Tk has a stable primary window
        # before any modal grabs focus. Without this, destroying a modal
        # CTkToplevel over a withdrawn root can tear down the interpreter
        # on Windows and the app silently exits.
        app.update_idletasks()
        center_mapped_window(app, app._monitor_anchor)
        if not prompt_if_needed(app):
            log.info("User declined responsible-use notice; exiting")
            app.destroy()
            return
        app.after_idle(app.initialize_default_tab)
        app.mainloop()
    except Exception:
        log.exception("NetRecon GUI crashed during startup")
        raise
