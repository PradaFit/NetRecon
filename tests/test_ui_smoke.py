import os
import threading
import time

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("NETRECON_RUN_UI_SMOKE") != "1",
    reason="set NETRECON_RUN_UI_SMOKE=1 on a graphical Windows session",
)


def _buttons(widget):
    import customtkinter as ctk

    found = []
    for child in widget.winfo_children():
        if isinstance(child, ctk.CTkButton):
            found.append(child)
        found.extend(_buttons(child))
    return found


def _pump(app, predicate=lambda: True, timeout=3):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        app.update()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_all_visible_buttons_are_bound_and_safe_to_invoke(monkeypatch):
    import tkinter.filedialog as filedialog
    import tkinter.messagebox as messagebox
    import webbrowser

    from gui.app import PradaFitApp

    monkeypatch.setattr(filedialog, "askopenfilename", lambda **kwargs: "")
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **kwargs: "")
    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: False)
    monkeypatch.setattr(messagebox, "showinfo", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showwarning", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: None)
    monkeypatch.setattr(webbrowser, "open_new_tab", lambda url: True)

    app = PradaFitApp()
    app.withdraw()
    try:
        assert app._dns_tab is None
        assert app._scan_tab is None
        assert app._geo_tab is None
        assert app._hist_tab is None
        app.initialize_default_tab()
        for tab_name in ("Port Scanner", "Geolocation", "History", "DNS Lookup"):
            app.tabview.set(f"  {tab_name}  ")
            app._on_tab_change()
            app.update()

        if os.name == "nt":
            assert app._window_icon_path is not None
            assert app._window_icon_path.name == "NetRecon.ico"

        class OfflineGeoEngine:
            MAX_BULK_TARGETS = 1000

            @staticmethod
            def get_my_ip():
                return None

        app.geo_tab.engine = OfflineGeoEngine()
        assert _pump(app)
        buttons = _buttons(app)
        labels = {button.cget("text") for button in buttons}
        expected = {
            "About",
            "Resolve",
            "Reverse Lookup",
            "All Records",
            "Propagation Check",
            "WHOIS",
            "Zone Transfer",
            "Start Scan",
            "Cancel",
            "Locate IP",
            "My Public IP",
            "Traceroute Map",
            "Bulk Lookup",
            "Refresh",
            "Delete",
            "Export All",
            "Clear All",
            "Export JSON",
            "Export CSV",
            "Export HTML",
            "Generate Map",
            "Copy",
            "Clear",
        }
        assert expected <= labels
        assert all(callable(button.cget("command")) for button in buttons)

        # Empty-input and no-data paths must give feedback without raising.
        for button in buttons:
            if button.cget("text") not in {"About", "Start Scan", "Cancel"}:
                button.invoke()
                app.update()

        about_button = next(button for button in buttons if button.cget("text") == "About")
        about_button.invoke()
        app.update()
        about = app._about_dialog
        about.withdraw()
        if os.name == "nt":
            assert about._window_icon_path is not None
        about_buttons = _buttons(about)
        assert {button.cget("text") for button in about_buttons} >= {
            "GitHub Repository",
            "Report an Issue",
            "Privacy Policy",
            "Export Diagnostic Log",
            "Close",
        }
        for button in about_buttons:
            if button.cget("text") != "Close":
                button.invoke()
                app.update()
        next(button for button in about_buttons if button.cget("text") == "Close").invoke()
        app.update()

        from gui import first_run

        monkeypatch.setattr(
            first_run.preferences, "accept_responsible_use", lambda version: True
        )
        notice = first_run.ResponsibleUseDialog(app)
        notice.withdraw()
        app.update()
        if os.name == "nt":
            assert notice._window_icon_path is not None
        notice_buttons = _buttons(notice)
        assert {button.cget("text") for button in notice_buttons} == {
            "Continue",
            "Exit NetRecon",
        }
        assert next(
            button for button in notice_buttons if button.cget("text") == "Continue"
        ).cget("state") == "disabled"
        notice._agree_var.set(True)
        notice._on_toggle()
        next(
            button for button in notice_buttons if button.cget("text") == "Continue"
        ).invoke()
        app.update()
        assert notice.accepted is True
    finally:
        if app.winfo_exists():
            app._on_close()


def test_scan_start_and_cancel_buttons_complete_promptly(monkeypatch):
    import tkinter.messagebox as messagebox

    from gui.app import PradaFitApp
    from netrecon.scan_engine import SCAN_PROFILES, ScanResult

    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    app = PradaFitApp()
    app.withdraw()

    class BlockingEngine:
        def __init__(self):
            self.stop = threading.Event()

        def scan(self, *args, **kwargs):
            kwargs["callback"](
                "  [ 35.0%] Nmap SYN Stealth Scan; about 0m 05s remaining"
            )
            self.stop.wait(5)
            return ScanResult(
                target="127.0.0.1",
                profile="Native Quick",
                arguments="",
                error="Scan cancelled by user",
                cancelled=True,
            )

        def cancel(self):
            self.stop.set()
            return True

    try:
        tab = app.scan_tab
        assert _pump(app)

        # Exercise both the programmatic wrapper and the callback used by real
        # OptionMenu selections. Every transition must restore the active
        # backend's speed control.
        for profile_key in (
            "default",
            "intense",
            "vuln",
            "vuln_extended",
            "comprehensive_extended",
            "quick",
        ):
            tab.profile.set(SCAN_PROFILES[profile_key]["name"])
            app.update()
            assert tab.timing.dropdown.cget("state") == "normal"
            assert tab.timing.winfo_manager() == "pack"
            assert tab.speed.dropdown.cget("state") == "disabled"
            assert tab.speed.winfo_manager() == ""

        for profile_key in ("native_quick", "native_full", "native_custom"):
            tab.profile.dropdown._dropdown_callback(SCAN_PROFILES[profile_key]["name"])
            app.update()
            assert tab.speed.dropdown.cget("state") == "normal"
            assert tab.speed.winfo_manager() == "pack"
            assert tab.timing.dropdown.cget("state") == "disabled"
            assert tab.timing.winfo_manager() == ""

        # An extended profile cannot start unless the operator explicitly
        # confirms the work-order scope warning.
        class MustNotRunEngine:
            def scan(self, *args, **kwargs):
                pytest.fail("extended scan started without confirmation")

            def cancel(self):
                return False

        monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: False)
        tab.engine = MustNotRunEngine()
        tab.profile.set(SCAN_PROFILES["vuln_extended"]["name"])
        tab.target.set("127.0.0.1")
        tab.scan_btn.invoke()
        app.update()
        assert tab._scanning is False
        assert tab.scan_btn.cget("state") == "normal"

        monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
        tab.profile.set(SCAN_PROFILES["native_quick"]["name"])
        engine = BlockingEngine()
        tab.engine = engine
        tab.target.set("127.0.0.1")
        tab.scan_btn.invoke()
        assert _pump(app, lambda: tab._scanning)
        assert _pump(app, lambda: tab._progress_percent == 35.0)
        assert tab.progress.cget("mode") == "determinate"
        assert tab.progress.get() == pytest.approx(0.35)
        assert "35.0%" in app.status_bar._label.cget("text")
        started = time.perf_counter()
        tab.cancel_btn.invoke()
        assert _pump(app, lambda: not tab._scanning)
        assert time.perf_counter() - started < 1.0
        assert "cancelled" in app.status_bar._label.cget("text").lower()
        assert tab.scan_btn.cget("state") == "normal"
        assert tab.cancel_btn.cget("state") == "disabled"
    finally:
        if app.winfo_exists():
            app._on_close()


def test_immediate_cancel_during_worker_startup_is_not_lost(monkeypatch):
    import tkinter.messagebox as messagebox

    from gui.app import PradaFitApp
    from netrecon.scan_engine import ScanResult

    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    app = PradaFitApp()
    app.withdraw()

    class SlowStartingEngine:
        def __init__(self):
            self.active = threading.Event()
            self.stop = threading.Event()

        def scan(self, *args, **kwargs):
            time.sleep(0.05)
            self.active.set()
            self.stop.wait(5)
            return ScanResult(
                target="127.0.0.1",
                profile="Native Quick",
                arguments="",
                error="Scan cancelled by user",
                cancelled=True,
            )

        def cancel(self):
            if not self.active.is_set():
                return False
            self.stop.set()
            return True

    try:
        engine = SlowStartingEngine()
        app.scan_tab.engine = engine
        app.scan_tab.target.set("127.0.0.1")
        app.scan_tab.scan_btn.invoke()
        app.scan_tab.cancel_btn.invoke()
        assert _pump(app, lambda: not app.scan_tab._scanning)
        assert engine.stop.is_set()
        assert "cancelled" in app.status_bar._label.cget("text").lower()
    finally:
        if app.winfo_exists():
            app._on_close()


def test_port_scanner_tab_does_not_wait_for_nmap_version(monkeypatch):
    from gui.app import PradaFitApp
    from netrecon.platform_utils import platform_info

    lookup_started = threading.Event()
    release_lookup = threading.Event()

    monkeypatch.setattr(platform_info, "find_nmap", lambda: r"C:\Nmap\nmap.exe")

    def slow_version_lookup():
        lookup_started.set()
        release_lookup.wait(3)
        return "Nmap version 7.98"

    monkeypatch.setattr(platform_info, "get_nmap_version", slow_version_lookup)

    app = PradaFitApp()
    app.withdraw()
    try:
        started_at = time.perf_counter()
        tab = app.scan_tab
        construction_time = time.perf_counter() - started_at

        assert construction_time < 0.75
        assert lookup_started.wait(1)
        assert "Nmap: detected" in tab._nmap_status_label.cget("text")

        release_lookup.set()
        assert _pump(
            app,
            lambda: "Nmap version 7.98" in tab._nmap_status_label.cget("text"),
        )
    finally:
        release_lookup.set()
        if app.winfo_exists():
            app._on_close()
