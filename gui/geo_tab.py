"""Geolocation tab"""

import threading
from pathlib import Path
from tkinter import filedialog, messagebox
import customtkinter as ctk

from .theme import COLORS, FONT_FAMILY
from .ui_dispatcher import UiDispatcher
from .widgets import (
    OutputConsole,
    ExportBar,
    LabeledEntry,
)
from netrecon import GeoEngine, ExportEngine
from netrecon.platform_utils import platform_info
from netrecon import logger as nr_logger

log = nr_logger.get_logger("gui.geo")


class GeoTab(ctk.CTkFrame, UiDispatcher):

    def __init__(self, master, status_bar=None, db=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status_bar
        self.db = db
        self.engine = GeoEngine()
        self._last_results = None
        self._geo_list = []
        self._busy = False
        self._action_buttons = []
        self._build_ui()
        self._init_ui_dispatcher()

    def _build_ui(self):
        # input row
        inp = ctk.CTkFrame(self, fg_color="transparent")
        inp.pack(fill="x", padx=10, pady=(10, 4))

        self.target = LabeledEntry(inp, "Target (IP or domain)", "8.8.8.8", width=280)
        self.target.pack(side="left", padx=(0, 8))

        # button row
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=4)

        btn_style = {
            "height": 34,
            "corner_radius": 8,
            "font": (FONT_FAMILY, 13, "bold"),
            "fg_color": COLORS["accent_dim"],
            "hover_color": COLORS["accent_hover"],
            "text_color": COLORS["text_bright"],
        }

        buttons = [
            ("Locate IP", self._on_locate),
            ("My Public IP", self._on_my_ip),
            ("Traceroute Map", self._on_traceroute),
            ("Bulk Lookup", self._on_bulk),
        ]
        for text, cmd in buttons:
            button = ctk.CTkButton(
                btn_frame, text=text, command=cmd, width=140, **btn_style
            )
            button.pack(side="left", padx=(0, 6))
            self._action_buttons.append(button)

        # info cards frame
        self._cards_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            height=120,
        )
        self._cards_frame.pack(fill="x", padx=10, pady=(4, 2))

        # output
        self.console = OutputConsole(self)
        self.console.pack(fill="both", expand=True, padx=10, pady=(2, 4))

        # export bar
        self.export_bar = ExportBar(
            self,
            on_json=self._export_json,
            on_csv=self._export_csv,
            on_html=self._export_html,
            on_map=self._export_map,
            on_copy=self._copy,
            on_clear=self._clear,
        )
        self.export_bar.pack(fill="x", padx=10, pady=(0, 10))

    # actions

    def _run_bg(self, fn, *args):
        if self._busy:
            self._set_status("A geolocation operation is already running", "warning")
            return
        self._set_busy(True)

        def guarded():
            try:
                fn(*args)
            except Exception as exc:
                log.exception("Unhandled geolocation worker error")
                self.post_ui(self._background_error, str(exc))
            finally:
                self.post_ui(self._set_busy, False)

        threading.Thread(target=guarded, daemon=True).start()

    def _set_busy(self, busy):
        self._busy = bool(busy)
        state = "disabled" if self._busy else "normal"
        for button in self._action_buttons:
            button.configure(state=state)

    def _background_error(self, message):
        self.console.clear()
        self.console.append_line(f"  Error: {message}", "error")
        self._set_status("Geolocation operation failed", "error")

    def _require_target(self):
        target = self.target.get()
        if not target:
            self._set_status("Enter an IP address or domain first", "error")
            return None
        return target

    def _on_locate(self):
        target = self._require_target()
        if target is None:
            return
        self._set_status(f"Geolocating {target} ...")

        def task():
            result = self.engine.locate(target)
            self._last_results = result.to_dict()
            self._geo_list = [result]
            self.post_ui(self._display_single, result)
            self.post_ui(
                self._set_status,
                result.error or "Geolocation lookup complete",
                "error" if result.error else "success",
            )
            self._save("Geolocation", target, self._last_results)

        self._run_bg(task)

    def _on_my_ip(self):
        self._set_status("Detecting public IP ...")

        def task():
            ip = self.engine.get_my_ip()
            if ip:
                self.post_ui(self.target.set, ip)
                result = self.engine.locate(ip)
                self._last_results = result.to_dict()
                self._geo_list = [result]
                self.post_ui(self._display_single, result)
                self.post_ui(
                    self._set_status,
                    result.error or f"Your public IP: {ip}",
                    "error" if result.error else "success",
                )
                self._save("Geolocation", ip, self._last_results)
            else:
                self.post_ui(self._set_status, "Could not detect public IP", "error")

        self._run_bg(task)

    def _on_traceroute(self):
        target = self._require_target()
        if target is None:
            return

        # One-shot heads-up so the user knows why the button looks idle.
        # Skipped on subsequent runs in the same session.
        if not getattr(self, "_tracert_warned", False):
            messagebox.showinfo(
                "Traceroute",
                "Traceroute walks every router between you and the target,\n"
                "one hop at a time, then geolocates each hop.\n\n"
                "Expect roughly 5 to 20 seconds depending on the path length\n"
                "and how quickly each router replies. Slow or silent hops\n"
                "add to the total. The GUI stays responsive while it runs.",
                parent=self,
            )
            self._tracert_warned = True

        self._set_status(f"Running traceroute to {target} (5-20s typical) ...")

        def task():
            results = self.engine.traceroute_geo(target)
            self._last_results = [r.to_dict() for r in results]
            self._geo_list = results
            self.post_ui(self._display_traceroute, results)
            succeeded = sum(not result.error for result in results)
            self.post_ui(
                self._set_status,
                f"Traceroute complete: {succeeded}/{len(results)} hops resolved",
                "success" if succeeded else "warning",
            )
            self._save("Traceroute Geo", target, self._last_results)

        self._run_bg(task)

    def _on_bulk(self):
        path = filedialog.askopenfilename(
            title="Select file with IPs/domains (one per line)",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            if Path(path).stat().st_size > 1024 * 1024:
                raise ValueError("Bulk input files are limited to 1 MB")
            with open(path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
            if not targets:
                raise ValueError("The selected file contains no targets")
            if len(targets) > self.engine.MAX_BULK_TARGETS:
                raise ValueError(
                    f"Bulk lookup is limited to {self.engine.MAX_BULK_TARGETS} targets"
                )
        except Exception as e:
            self._set_status(f"Error reading file: {e}", "error")
            return

        self._set_status(f"Bulk geolocating {len(targets)} targets ...")

        def task():
            results = self.engine.bulk_locate(targets)
            self._last_results = [r.to_dict() for r in results]
            self._geo_list = results
            self.post_ui(self._display_bulk, results)
            succeeded = sum(not result.error for result in results)
            self.post_ui(
                self._set_status,
                f"Bulk lookup complete: {succeeded}/{len(results)} successful",
                "success" if succeeded == len(results) else "warning",
            )

        self._run_bg(task)


    def _clear_cards(self):
        for widget in self._cards_frame.winfo_children():
            widget.destroy()

    def _display_single(self, result):
        self._clear_cards()
        self.console.clear()

        if result.error:
            self.console.append_line(f"  Error: {result.error}", "error")
            return

        self._build_info_card(result)
        self._format_geo_console(result)

    def _display_traceroute(self, results):
        self._clear_cards()
        self.console.clear()
        self.console.append_line("  Traceroute Geolocation", "header")
        self.console.append_line("")

        self.console.append_line(
            f"  {'HOP':<5} {'IP':<18} {'CITY':<20} {'REGION':<16} {'COUNTRY':<12} {'ISP'}",
            "bold",
        )

        for i, r in enumerate(results, 1):
            if r.error:
                self.console.append_line(f"  {i:<5} {'*':<18} (no response)", "dim")
            else:
                self.console.append_line(
                    f"  {i:<5} {r.ip:<18} {r.city:<20} {r.region:<16} "
                    f"{r.country:<12} {r.isp}",
                    "success" if r.city else "dim",
                )

        self.console.append_line(f"\n  Total hops: {len(results)}", "info")
        self.console.append_line(
            "  Use 'Generate Map' to create an interactive route map.", "info"
        )

    def _display_bulk(self, results):
        self._clear_cards()
        self.console.clear()
        self.console.append_line("  Bulk Geolocation Results", "header")
        self.console.append_line("")

        self.console.append_line(
            f"  {'IP':<18} {'CITY':<20} {'REGION':<16} {'COUNTRY':<12} {'ISP'}", "bold"
        )

        for r in results:
            if r.error:
                self.console.append_line(f"  {r.ip:<18} ERROR: {r.error}", "error")
            else:
                self.console.append_line(
                    f"  {r.ip:<18} {r.city:<20} {r.region:<16} "
                    f"{r.country:<12} {r.isp}",
                    "success",
                )

        self.console.append_line(f"\n  Total: {len(results)} targets", "info")

    def _build_info_card(self, result):
        card = ctk.CTkFrame(
            self._cards_frame,
            fg_color=COLORS["bg_card"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        card.pack(fill="x", pady=4, padx=4)

        # Two-column layout
        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=12, pady=8)

        right = ctk.CTkFrame(card, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True, padx=12, pady=8)

        left_fields = [
            ("IP", result.ip),
            ("Location", result.location_string),
            (
                "Coordinates",
                (
                    f"{result.latitude}, {result.longitude}"
                    if result.coordinates
                    else "N/A"
                ),
            ),
            ("Timezone", result.timezone),
        ]
        right_fields = [
            ("ISP", result.isp),
            ("Organization", result.org),
            ("ASN", result.asn),
            ("Reverse DNS", result.reverse_dns or "N/A"),
        ]

        for fields, parent in [(left_fields, left), (right_fields, right)]:
            for label, value in fields:
                row = ctk.CTkFrame(parent, fg_color="transparent")
                row.pack(fill="x", pady=1)
                ctk.CTkLabel(
                    row,
                    text=f"{label}:",
                    font=(FONT_FAMILY, 11),
                    text_color=COLORS["text_dim"],
                    width=100,
                    anchor="w",
                ).pack(side="left")
                ctk.CTkLabel(
                    row,
                    text=str(value),
                    font=(FONT_FAMILY, 11),
                    text_color=COLORS["text"],
                    anchor="w",
                ).pack(side="left", fill="x")

    def _format_geo_console(self, r):
        self.console.append_line(f"  Geolocation: {r.ip}", "header")
        self.console.append_line("")
        fields = [
            ("Country", f"{r.country} ({r.country_code})"),
            ("Region", r.region),
            ("City", r.city),
            ("ZIP", r.zip_code),
            ("Latitude", str(r.latitude)),
            ("Longitude", str(r.longitude)),
            ("Timezone", r.timezone),
            ("ISP", r.isp),
            ("Organization", r.org),
            ("ASN", r.asn),
            ("AS Name", r.as_name),
            ("Reverse DNS", r.reverse_dns or "N/A"),
            ("Proxy", "Yes" if r.is_proxy else "No"),
            ("Mobile", "Yes" if r.is_mobile else "No"),
            ("Hosting", "Yes" if r.is_hosting else "No"),
            ("Source", r.source),
        ]
        for label, value in fields:
            if value:
                self.console.append_line(f"  {label:<16}  {value}", "info")

    # exports

    def _do_export(self, fn, ext, kind, **kwargs):
        if not self._last_results:
            messagebox.showinfo(
                "NetRecon",
                "Nothing to export. Run a lookup first.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=f".{ext}",
            filetypes=[(kind, f"*.{ext}")],
            initialfile=f"netrecon_geo.{ext}",
        )
        if not path:
            return
        try:
            out = fn(self._last_results, path, trusted=True, **kwargs)
        except Exception as e:
            log.exception("Geo export failed (%s)", ext)
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
            ExportEngine.to_html, "html", "HTML", title="Geolocation Report"
        )

    def _export_map(self):
        if not self._geo_list:
            messagebox.showinfo(
                "NetRecon",
                "No geolocation results to map. Run a lookup first.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".html",
            filetypes=[("HTML Map", "*.html")],
            initialfile="netrecon_map.html",
        )
        if not path:
            return
        try:
            result = ExportEngine.generate_map(self._geo_list, path, trusted=True)
        except Exception as e:
            log.exception("Map export failed")
            messagebox.showerror(
                "Map export failed",
                f"Could not write map to {path}\n\n{type(e).__name__}: {e}",
                parent=self,
            )
            self._set_status("Map export failed", "error")
            return
        if result:
            self._set_status(f"Map saved to {path}", "success")
            if not platform_info.open_file(path):
                messagebox.showwarning(
                    "Map saved",
                    f"The map was saved, but NetRecon could not open it automatically.\n\n{path}",
                    parent=self,
                )
        else:
            messagebox.showwarning(
                "Map export",
                "Failed to generate map. The 'folium' package is not installed.",
                parent=self,
            )
            self._set_status(
                "Failed to generate map (folium may not be installed)", "error"
            )

    def _copy(self):
        text = self.console.get_text()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("Copied to clipboard", "success")

    def _clear(self):
        self.console.clear()
        self._clear_cards()
        self._last_results = None
        self._geo_list = []

    def _set_status(self, msg, level="info"):
        if self.status:
            self.status.set_message(msg, level)

    def _save(self, scan_type, target, data):
        if self.db:
            try:
                self.db.save(scan_type, target, data)
            except Exception:
                log.exception("Failed to save %s to history", scan_type)
