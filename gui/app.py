"""Main application window for NetRecon."""

import sys
import customtkinter as ctk

from .theme import COLORS, FONT_FAMILY, FONT_MONO
from .widgets import StatusBar
from .dns_tab import DNSTab
from .scan_tab import ScanTab
from .geo_tab import GeoTab
from .history_tab import HistoryTab
from .first_run import prompt_if_needed
from .about_dialog import AboutDialog
from netrecon import DatabaseManager, __version__
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


class PradaFitApp(ctk.CTk):
    """Primary window with tabbed interface."""

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(
            f"NetRecon v{__version__}: Network Reconnaissance Toolkit  |  by PradaFit"
        )
        self.geometry("1300x860")
        self.minsize(960, 600)

        try:
            if platform_info.is_windows:
                self.iconbitmap(default="")
        except Exception as exc:
            log.debug("Could not apply window icon: %s", type(exc).__name__)

        self.configure(fg_color=COLORS["bg_dark"])

        # Shared db
        self.db = DatabaseManager()
        self._about_dialog = None

        self._build_ui()
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

        dns_frame = self.tabview.add("  DNS Lookup  ")
        scan_frame = self.tabview.add("  Port Scanner  ")
        geo_frame = self.tabview.add("  Geolocation  ")
        hist_frame = self.tabview.add("  History  ")

        self.dns_tab = DNSTab(dns_frame, status_bar=self.status_bar, db=self.db)
        self.dns_tab.pack(fill="both", expand=True)

        self.scan_tab = ScanTab(scan_frame, status_bar=self.status_bar, db=self.db)
        self.scan_tab.pack(fill="both", expand=True)

        self.geo_tab = GeoTab(geo_frame, status_bar=self.status_bar, db=self.db)
        self.geo_tab.pack(fill="both", expand=True)

        self.hist_tab = HistoryTab(hist_frame, status_bar=self.status_bar, db=self.db)
        self.hist_tab.pack(fill="both", expand=True)

        self.tabview.set("  DNS Lookup  ")

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
        self.scan_tab.shutdown()
        self.destroy()

    def _on_tab_change(self):
        try:
            name = self.tabview.get()
        except Exception as exc:
            log.warning("Could not read selected tab: %s", type(exc).__name__)
            return
        if name.strip() == "History":
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
        if not prompt_if_needed(app):
            log.info("User declined responsible-use notice; exiting")
            app.destroy()
            return
        app.mainloop()
    except Exception:
        log.exception("NetRecon GUI crashed during startup")
        raise
