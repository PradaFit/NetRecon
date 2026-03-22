"""Port Scanner tab"""

import re
import threading
from tkinter import filedialog
import customtkinter as ctk

from .theme import COLORS, FONT_FAMILY
from .widgets import (
    OutputConsole,
    ExportBar,
    LabeledEntry,
    LabeledDropdown,
)
from netrecon import ScanEngine, ExportEngine, SCAN_PROFILES
from netrecon.platform_utils import platform_info


class ScanTab(ctk.CTkFrame):

    def __init__(self, master, status_bar=None, db=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status_bar
        self.db = db
        self.engine = ScanEngine()
        self._last_result = None
        self._scanning = False
        self._build_ui()

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
            row1, "Target (IP / Host / CIDR)", "192.168.1.0/24", width=260
        )
        self.target.pack(side="left", padx=(0, 8))

        self.ports = LabeledEntry(
            row1, "Ports (optional)", "22,80,443 or 1-1024", width=180
        )
        self.ports.pack(side="left", padx=(0, 8))

        profile_names = [SCAN_PROFILES[k]["name"] for k in SCAN_PROFILES]
        self._profile_keys = list(SCAN_PROFILES.keys())
        self.profile = LabeledDropdown(
            row1,
            "Scan Profile",
            profile_names,
            default=SCAN_PROFILES["native_quick"]["name"],
            width=200,
            command=self._on_profile_change,
        )
        self.profile.pack(side="left", padx=(0, 8))

        timing_values = [f"T{i}" for i in range(6)]
        self.timing = LabeledDropdown(
            row1, "Timing (nmap)", timing_values, default="T3", width=100
        )
        self.timing.pack(side="left", padx=(0, 8))

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
        self._on_profile_change(SCAN_PROFILES["native_quick"]["name"])

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
                self._desc_label.configure(text=desc)
                break

    def _get_selected_profile_key(self):
        selected = self.profile.get()
        for key, prof in SCAN_PROFILES.items():
            if prof["name"] == selected:
                return key
        return "native_quick"

    def _on_start_scan(self):
        target = self.target.get()
        if not target:
            return

        self._scanning = True
        self.scan_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.set(0)
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self.console.clear()
        self._set_status("Scanning ...", "info")

        custom = self.custom_args.get()
        profile_key = self._get_selected_profile_key()
        ports = self.ports.get() or None
        is_native = profile_key.startswith("native_")

        if not is_native and not custom:
            timing = self.timing.get()
            profile_args = SCAN_PROFILES.get(profile_key, {}).get("args", "")
            profile_args = re.sub(r"-T\d", timing, profile_args)
            custom_final = profile_args
        else:
            custom_final = custom if custom else None

        def callback(msg):
            self.after(0, self.console.append_line, msg, "info")

        def task():
            try:
                if is_native:
                    result = self.engine.scan(
                        target, profile=profile_key, ports=ports, callback=callback
                    )
                elif custom:
                    result = self.engine.scan(
                        target, custom_args=custom_final, ports=ports, callback=callback
                    )
                else:
                    result = self.engine.scan(
                        target,
                        profile=profile_key,
                        custom_args=custom_final,
                        ports=ports,
                        callback=callback,
                    )
                self._last_result = result
                self.after(0, self._scan_finished, result)
            except Exception as exc:
                self.after(0, self._scan_error, str(exc))

        threading.Thread(target=task, daemon=True).start()

    def _on_cancel(self):
        self.engine.cancel()
        self._set_status("Cancelling scan ...", "warning")

    def _scan_error(self, msg):
        self._scanning = False
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(0)
        self.console.append_line(f"\n  Error: {msg}", "error")
        self._set_status("Scan failed", "error")

    def _scan_finished(self, result):
        self._scanning = False
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1)

        if result.error:
            self.console.append_line(f"\n  Error: {result.error}", "error")
            self._set_status("Scan failed", "error")
        else:
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
                pass

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
            state_tag = "success" if host["state"] == "up" else "error"
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

    def _export_json(self):
        if not self._last_result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")]
        )
        if path:
            ExportEngine.to_json(self._last_result, path)
            self._set_status(f"Exported to {path}", "success")

    def _export_csv(self):
        if not self._last_result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")]
        )
        if path:
            ExportEngine.to_csv(self._last_result, path)
            self._set_status(f"Exported to {path}", "success")

    def _export_html(self):
        if not self._last_result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML", "*.html")]
        )
        if path:
            ExportEngine.to_html(self._last_result, path, title="Port Scan Report")
            self._set_status(f"Exported to {path}", "success")

    def _copy(self):
        text = self.console.get_text()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("Copied to clipboard", "success")

    def _clear(self):
        self.console.clear()
        self._last_result = None

    def _set_status(self, msg, level="info"):
        if self.status:
            self.status.set_message(msg, level)
