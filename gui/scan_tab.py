"""Port Scanner tab"""

import re
import threading
import time
from tkinter import filedialog, messagebox
import customtkinter as ctk

from .theme import COLORS, FONT_FAMILY
from .ui_dispatcher import UiDispatcher
from .widgets import (
    OutputConsole,
    ExportBar,
    LabeledEntry,
    LabeledDropdown,
)
from netrecon import ScanEngine, ExportEngine, SCAN_PROFILES
from netrecon.platform_utils import platform_info
from netrecon.config import get_section
from netrecon import logger as nr_logger

log = nr_logger.get_logger("gui.scan")


# GUI-side speed tiers. Maps a friendly label to the native scanner's
# concurrency setting. The default is intentionally moderate; the
# engine still supports higher values for users who explicitly opt in.
SPEED_TIERS = {
    "Safe (500)": 500,
    "Balanced (1500)": 1500,
    "Fast (4000)": 4000,
    "Extreme (8000)": 8000,
}
DEFAULT_SPEED = "Fast (4000)"
SCAN_PROGRESS_RE = re.compile(r"\[\s*(\d+(?:\.\d+)?)%\]\s*(.*)")


class ScanTab(ctk.CTkFrame, UiDispatcher):

    def __init__(self, master, status_bar=None, db=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status_bar
        self.db = db
        self._settings = get_section("scan")
        self.engine = ScanEngine()
        self._last_result = None
        self._scanning = False
        self._scan_started_at = None
        self._progress_percent = None
        self._progress_detail = ""
        self._last_console_progress_bucket = None
        self._build_ui()
        self._init_ui_dispatcher()

    def _build_ui(self):
        # availability banner
        nmap_ok = self.engine.is_available
        info_bar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=8)
        info_bar.pack(fill="x", padx=10, pady=(10, 2))

        if nmap_ok:
            ver = platform_info.get_nmap_version() or "detected"
            admin_s = "Yes" if platform_info.is_admin else "No"
            msg = (
                f"  Nmap: {ver}  |  Admin: {admin_s}  |  Native async TCP scanner ready"
            )
            ctk.CTkLabel(
                info_bar,
                text=msg,
                font=(FONT_FAMILY, 11),
                text_color=COLORS["text_dim"],
                anchor="w",
            ).pack(padx=10, pady=6)
        else:
            ctk.CTkLabel(
                info_bar,
                text="  Nmap not detected. Native async scanner is still available for TCP connect scans.",
                font=(FONT_FAMILY, 11),
                text_color=COLORS["warning"],
                anchor="w",
            ).pack(padx=10, pady=6)

        # inputs row 1
        row1 = ctk.CTkFrame(self, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(6, 2))

        self.target = LabeledEntry(
            row1, "Target (IP / Host / CIDR)", "192.168.1.10", width=260
        )
        self.target.pack(side="left", padx=(0, 8))

        self.ports = LabeledEntry(
            row1, "Ports (optional)", "22,80,443 or 1-1024", width=180
        )
        self.ports.pack(side="left", padx=(0, 8))

        profile_names = [SCAN_PROFILES[k]["name"] for k in SCAN_PROFILES]
        self._profile_keys = list(SCAN_PROFILES.keys())
        default_profile = self._settings.get("default_profile", "native_quick")
        if default_profile not in SCAN_PROFILES:
            default_profile = "native_quick"
        self.profile = LabeledDropdown(
            row1,
            "Scan Profile",
            profile_names,
            default=SCAN_PROFILES[default_profile]["name"],
            width=200,
            command=self._on_profile_change,
        )
        self.profile.pack(side="left", padx=(0, 8))

        timing_values = ["Profile default"] + [f"T{i}" for i in range(6)]
        default_timing = self._settings.get("default_timing", "Profile default")
        if default_timing not in timing_values:
            default_timing = "Profile default"
        self.speed_slot = ctk.CTkFrame(row1, fg_color="transparent")
        self.speed_slot.pack(side="left", padx=(0, 8))

        self.timing = LabeledDropdown(
            self.speed_slot,
            "Nmap Scan Speed",
            timing_values,
            default=default_timing,
            width=150,
        )

        try:
            configured_concurrency = int(
                self._settings.get("native_concurrency", 1500)
            )
        except (TypeError, ValueError):
            configured_concurrency = 4000
        default_speed = min(
            SPEED_TIERS,
            key=lambda label: abs(SPEED_TIERS[label] - configured_concurrency),
        )
        self.speed = LabeledDropdown(
            self.speed_slot,
            "Native Scan Speed",
            list(SPEED_TIERS.keys()),
            default=default_speed,
            width=150,
        )

        # inputs row 2
        row2 = ctk.CTkFrame(self, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=(2, 4))

        self.custom_args = LabeledEntry(
            row2,
            "Custom Nmap Arguments (overrides profile for nmap scans)",
            "-sV -T4 -p 1-1000",
            width=500,
        )
        self.custom_args.pack(side="left", padx=(0, 8))

        self._desc_label = ctk.CTkLabel(
            row2,
            text="",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._desc_label.pack(side="left", padx=(12, 0), fill="x", expand=True)
        self._on_profile_change(SCAN_PROFILES[default_profile]["name"])

        # buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=4)

        self.scan_btn = ctk.CTkButton(
            btn_frame,
            text="Start Scan",
            command=self._on_start_scan,
            width=140,
            height=36,
            corner_radius=8,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["text_bright"],
        )
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.cancel_btn = ctk.CTkButton(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
            width=100,
            height=36,
            corner_radius=8,
            font=(FONT_FAMILY, 13),
            fg_color="#4d0d0d",
            hover_color="#6d1d1d",
            text_color=COLORS["text"],
            state="disabled",
        )
        self.cancel_btn.pack(side="left", padx=(0, 6))

        self.progress = ctk.CTkProgressBar(
            btn_frame,
            width=200,
            height=12,
            fg_color=COLORS["bg_input"],
            progress_color=COLORS["accent"],
            corner_radius=6,
        )
        self.progress.pack(side="left", padx=(12, 0), pady=8)
        self.progress.set(0)

        # output
        self.console = OutputConsole(self)
        self.console.pack(fill="both", expand=True, padx=10, pady=(4, 4))

        # export bar
        self.export_bar = ExportBar(
            self,
            on_json=self._export_json,
            on_csv=self._export_csv,
            on_html=self._export_html,
            on_copy=self._copy,
            on_clear=self._clear,
        )
        self.export_bar.pack(fill="x", padx=10, pady=(0, 10))

    # profile selection

    def _on_profile_change(self, selected):
        for key, prof in SCAN_PROFILES.items():
            if prof["name"] == selected:
                desc = prof["description"]
                if prof.get("requires_admin"):
                    desc += "  [requires admin]"
                if prof.get("extended"):
                    desc += "  [explicit authorization required]"
                self._desc_label.configure(text=desc)
                native = bool(prof.get("native"))
                self.timing.dropdown.configure(state="disabled" if native else "normal")
                self.speed.dropdown.configure(state="normal" if native else "disabled")
                self.custom_args.entry.configure(state="disabled" if native else "normal")
                # Timing is Nmap's speed control, while concurrency is the
                # native scanner's speed control. Show the applicable control
                # instead of leaving an unrelated greyed-out control visible.
                if native:
                    self.timing.pack_forget()
                    if not self.speed.winfo_manager():
                        self.speed.pack(fill="x")
                else:
                    self.speed.pack_forget()
                    if not self.timing.winfo_manager():
                        self.timing.pack(fill="x")
                break

    def _get_selected_profile_key(self):
        selected = self.profile.get()
        for key, prof in SCAN_PROFILES.items():
            if prof["name"] == selected:
                return key
        return "native_quick"

    def _on_start_scan(self):
        if self._scanning:
            return
        target = self.target.get()
        if not target:
            self._set_status("Enter a target before starting a scan", "error")
            return

        custom = self.custom_args.get()
        profile_key = self._get_selected_profile_key()
        ports = self.ports.get() or None
        is_native = profile_key.startswith("native_")

        profile_data = SCAN_PROFILES.get(profile_key, {})
        custom_uses_full_vuln = bool(
            custom and re.search(r"--script(?:=|\s+)[^\s]*vuln(?:,|\s|$)", custom)
        )
        if profile_data.get("extended") or custom_uses_full_vuln:
            if not messagebox.askyesno(
                "NetRecon: Confirm Extended Nmap Checks",
                "This scan can run Nmap scripts tagged intrusive, exploit, or "
                "denial-of-service. Some scripts can discover or contact systems "
                "other than the target and may send service metadata to external "
                "providers.\n\nOnly continue when the work order explicitly "
                "authorizes these checks and their full network scope.\n\nContinue?",
            ):
                return

        speed_label = self.speed.get()
        concurrency = SPEED_TIERS.get(speed_label, SPEED_TIERS[DEFAULT_SPEED])

        if is_native and concurrency >= SPEED_TIERS["Extreme (8000)"]:
            if not messagebox.askyesno(
                "NetRecon: Confirm Extreme Speed",
                "Extreme speed opens a very large number of concurrent sockets. "
                "Only use this on networks you own or are authorized to scan, and "
                "only when you understand the load it can place on intermediate "
                "devices.\n\nContinue with Extreme speed?",
            ):
                return

        self._scanning = True
        self._scan_started_at = time.perf_counter()
        self._progress_percent = None
        self._progress_detail = ""
        self._last_console_progress_bucket = None
        self.scan_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal", text="Cancel")
        self.progress.set(0)
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self.console.clear()
        self._set_status("Scanning ...", "info")
        self.after(1000, self._refresh_scan_elapsed)

        timing_value = self.timing.get()
        timing = (
            timing_value
            if not is_native and not custom and timing_value != "Profile default"
            else None
        )

        def callback(msg):
            match = SCAN_PROGRESS_RE.search(msg)
            if not match:
                self.post_ui(self.console.append_line, msg, "info")
                return
            percent = max(0.0, min(float(match.group(1)), 100.0))
            detail = match.group(2).strip()
            self.post_ui(self._update_scan_progress, percent, detail)

            # Keep the output useful without adding one line every second.
            bucket = (detail.split(";", 1)[0], int(percent) // 10)
            if bucket != self._last_console_progress_bucket:
                self._last_console_progress_bucket = bucket
                self.post_ui(self.console.append_line, msg, "info")

        def task():
            try:
                result = self.engine.scan(
                    target,
                    profile=profile_key,
                    custom_args=custom or None,
                    ports=ports,
                    callback=callback,
                    timing=timing,
                    concurrency=concurrency if is_native else None,
                )
                self.post_ui(self._scan_finished, result)
            except Exception as exc:
                log.exception("Unhandled scan worker error")
                self.post_ui(self._scan_error, str(exc))

        threading.Thread(target=task, daemon=True).start()

    def _update_scan_progress(self, percent, detail):
        if not self._scanning:
            return
        self._progress_percent = percent
        self._progress_detail = detail
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(percent / 100.0)
        self._refresh_scan_elapsed(schedule_next=False)

    def _refresh_scan_elapsed(self, schedule_next=True):
        if not self._scanning or self._scan_started_at is None:
            return
        elapsed = int(time.perf_counter() - self._scan_started_at)
        if self._progress_percent is None:
            text = f"Scanning ... {elapsed}s elapsed"
        else:
            text = (
                f"{self._progress_detail} | {self._progress_percent:.1f}% | "
                f"{elapsed}s elapsed"
            )
        self._set_status(text, "info")
        if schedule_next:
            self.after(1000, self._refresh_scan_elapsed)

    def _on_cancel(self):
        if not self._scanning:
            return
        self.cancel_btn.configure(state="disabled", text="Cancelling...")
        if self.engine.cancel():
            self._set_status("Cancelling scan ...", "warning")
        else:
            # A click can land in the few milliseconds between creating the
            # worker thread and the engine marking itself active. Retry off the
            # UI thread so that even this immediate-cancel case is honored.
            self._set_status("Cancelling scan ...", "warning")

            def cancel_when_started():
                for _ in range(100):
                    if not self._scanning:
                        return
                    if self.engine.cancel():
                        return
                    threading.Event().wait(0.005)

            threading.Thread(target=cancel_when_started, daemon=True).start()

    def _scan_error(self, msg):
        self._scanning = False
        self._scan_started_at = None
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled", text="Cancel")
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(0)
        self.console.append_line(f"\n  Error: {msg}", "error")
        self._set_status("Scan failed", "error")

    def _scan_finished(self, result):
        self._scanning = False
        self._scan_started_at = None
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled", text="Cancel")
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(0 if result.cancelled else 1)

        if result.cancelled:
            self._last_result = None
            self.console.append_line("\n  Scan cancelled.", "warning")
            self._set_status("Scan cancelled", "warning")
        elif result.error:
            self._last_result = None
            self.console.append_line(f"\n  Error: {result.error}", "error")
            self._set_status("Scan failed", "error")
        else:
            self._last_result = result
            self._display_result(result)
            self._set_status(
                f"Scan complete: {result.total_hosts} hosts, "
                f"{result.total_open_ports} open ports ({result.scan_time}s)",
                "success",
            )

        if self.db and not result.error:
            try:
                summary = (
                    f"{result.total_hosts} hosts, {result.total_open_ports} open ports"
                )
                self.db.save("Port Scan", result.target, result, summary)
            except Exception:
                log.exception("Failed to save scan to history")
                self._set_status("Scan finished but could not save to history", "warning")

    def _display_result(self, result):
        self.console.append_line("")
        self.console.append_line(f"  Scan Results -- {result.target}", "header")
        self.console.append_line(
            f"  Profile: {result.profile}  |  Args: {result.arguments}", "dim"
        )
        if result.command_line:
            self.console.append_line(f"  Command: {result.command_line}", "dim")
        self.console.append_line(f"  Duration: {result.scan_time}s", "dim")
        self.console.append_line("")

        for host in result.hosts:
            state_tag = {
                "up": "success",
                "down": "error",
                "unknown": "warning",
            }.get(host["state"], "warning")
            self.console.append_line(
                f"  Host: {host['ip']}  ({host['hostname']})  [{host['state']}]",
                state_tag,
            )

            if host.get("os_matches"):
                for om in host["os_matches"]:
                    self.console.append_line(
                        f"    OS: {om['name']} (accuracy: {om['accuracy']}%)", "info"
                    )

            if host.get("ports"):
                self.console.append_line(
                    f"    {'PORT':<10} {'STATE':<12} {'SERVICE':<16} {'VERSION'}",
                    "bold",
                )
                for p in host["ports"]:
                    state_color = {
                        "open": "success",
                        "closed": "error",
                        "filtered": "warning",
                    }.get(p["state"], None)
                    version = f"{p['product']} {p['version']}".strip()
                    self.console.append_line(
                        f"    {p['port']}/{p['protocol']:<6} {p['state']:<12} "
                        f"{p['service']:<16} {version}",
                        state_color,
                    )

            if host.get("scripts"):
                self.console.append_line("\n    Scripts:", "info")
                for name, output in host["scripts"].items():
                    self.console.append_line(f"      [{name}]", "warning")
                    for line in str(output).splitlines():
                        self.console.append_line(f"        {line}", "dim")

            self.console.append_line("")

    # exports

    def _do_export(self, fn, ext, kind, **kwargs):
        if not self._last_result:
            messagebox.showinfo(
                "NetRecon",
                "Nothing to export. Run a scan first.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=f".{ext}",
            filetypes=[(kind, f"*.{ext}")],
            initialfile=f"netrecon_scan.{ext}",
        )
        if not path:
            return
        try:
            out = fn(self._last_result, path, trusted=True, **kwargs)
        except Exception as e:
            log.exception("Export failed (%s)", ext)
            messagebox.showerror(
                "Export failed",
                f"Could not export to {path}\n\n{type(e).__name__}: {e}",
                parent=self,
            )
            self._set_status("Export failed", "error")
            return
        if not out:
            messagebox.showwarning(
                "Export",
                "Nothing to write (no rows). Try a different format.",
                parent=self,
            )
            return
        self._set_status(f"Exported to {out}", "success")
        messagebox.showinfo("Export complete", f"Saved to:\n{out}", parent=self)

    def _export_json(self):
        self._do_export(ExportEngine.to_json, "json", "JSON")

    def _export_csv(self):
        self._do_export(ExportEngine.to_csv, "csv", "CSV")

    def _export_html(self):
        self._do_export(
            ExportEngine.to_html, "html", "HTML", title="Port Scan Report"
        )

    def _copy(self):
        text = self.console.get_text()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("Copied to clipboard", "success")

    def _clear(self):
        self.console.clear()
        self._last_result = None

    def shutdown(self):
        """Stop any active backend before the window closes."""
        if self._scanning:
            self.engine.cancel()

    def _set_status(self, msg, level="info"):
        if self.status:
            self.status.set_message(msg, level)
