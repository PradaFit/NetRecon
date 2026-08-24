"""DNS Lookup tab"""

import threading
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
from netrecon import DNSEngine, ExportEngine, RECORD_TYPES
from netrecon import logger as nr_logger

log = nr_logger.get_logger("gui.dns")


class DNSTab(ctk.CTkFrame, UiDispatcher):

    def __init__(self, master, status_bar=None, db=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status_bar
        self.db = db
        self.engine = DNSEngine()
        self._last_results = None
        self._busy = False
        self._action_buttons = []
        self._build_ui()
        self._init_ui_dispatcher()

    def _build_ui(self):
        # ---- input row ----
        inp = ctk.CTkFrame(self, fg_color="transparent")
        inp.pack(fill="x", padx=10, pady=(10, 4))

        self.target = LabeledEntry(
            inp, "Target (domain or IP)", "example.com", width=260
        )
        self.target.pack(side="left", padx=(0, 8))

        self.record_type = LabeledDropdown(
            inp,
            "Record Type",
            ["ALL"] + RECORD_TYPES,
            default="A",
            width=100,
        )
        self.record_type.pack(side="left", padx=(0, 8))

        self.dns_server = LabeledEntry(
            inp, "DNS Server (optional)", "8.8.8.8", width=160
        )
        self.dns_server.pack(side="left", padx=(0, 8))

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
            ("Resolve", self._on_resolve),
            ("Reverse Lookup", self._on_reverse),
            ("All Records", self._on_all_records),
            ("Propagation Check", self._on_propagation),
            ("WHOIS", self._on_whois),
            ("Zone Transfer", self._on_zone_transfer),
        ]
        for text, cmd in buttons:
            button = ctk.CTkButton(
                btn_frame, text=text, command=cmd, width=130, **btn_style
            )
            button.pack(side="left", padx=(0, 6))
            self._action_buttons.append(button)

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

    # actions

    def _run_bg(self, fn, *args):
        if self._busy:
            self._set_status("A DNS operation is already running", "warning")
            return
        self._set_busy(True)

        def guarded():
            try:
                fn(*args)
            except Exception as exc:
                log.exception("Unhandled DNS worker error")
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
        self._set_status("DNS operation failed", "error")

    def _require_target(self):
        target = self.target.get()
        if not target:
            self._set_status("Enter a domain or IP address first", "error")
            return None
        return target

    def _on_resolve(self):
        target = self._require_target()
        if target is None:
            return
        rtype = self.record_type.get()
        ns = self.dns_server.get() or None
        self._set_status(f"Resolving {target} ...")

        def task():
            if rtype == "ALL":
                results = self.engine.get_all_records(target)
                self._last_results = [r.to_dict() for r in results]
                self.post_ui(self._display_multi_dns, results)
            else:
                result = self.engine.resolve(target, rtype, ns)
                self._last_results = result.to_dict()
                self.post_ui(self._display_dns, result)
            if rtype == "ALL":
                succeeded = sum(bool(r.records) for r in results)
                level = "success" if succeeded else "error"
                message = f"Completed: {succeeded}/{len(results)} record types returned data"
            else:
                level = "error" if result.error else "success"
                message = result.error or "DNS lookup complete"
            self.post_ui(self._set_status, message, level)
            self._save("DNS Resolve", target, self._last_results)

        self._run_bg(task)

    def _on_reverse(self):
        target = self._require_target()
        if target is None:
            return
        self._set_status(f"Reverse lookup on {target} ...")

        def task():
            result = self.engine.reverse_lookup(target)
            self._last_results = result.to_dict()
            self.post_ui(self._display_dns, result)
            self.post_ui(
                self._set_status,
                result.error or "Reverse lookup complete",
                "error" if result.error else "success",
            )
            self._save("DNS Reverse", target, self._last_results)

        self._run_bg(task)

    def _on_all_records(self):
        target = self._require_target()
        if target is None:
            return
        self._set_status(f"Querying all record types for {target} ...")

        def task():
            results = self.engine.get_all_records(target)
            self._last_results = [r.to_dict() for r in results]
            self.post_ui(self._display_multi_dns, results)
            succeeded = sum(bool(r.records) for r in results)
            self.post_ui(
                self._set_status,
                f"Completed: {succeeded}/{len(results)} record types returned data",
                "success" if succeeded else "error",
            )
            self._save("DNS All Records", target, self._last_results)

        self._run_bg(task)

    def _on_propagation(self):
        target = self._require_target()
        if target is None:
            return
        rtype = self.record_type.get()
        if rtype == "ALL":
            rtype = "A"
        self._set_status(f"Checking DNS propagation for {target} ...")

        def task():
            results = self.engine.propagation_check(target, rtype)
            self._last_results = [r.to_dict() for r in results]
            self.post_ui(self._display_propagation, results)
            succeeded = sum(not r.error for r in results)
            self.post_ui(
                self._set_status,
                f"Propagation check: {succeeded}/{len(results)} resolvers replied",
                "success" if succeeded == len(results) else "warning",
            )
            self._save("DNS Propagation", target, self._last_results)

        self._run_bg(task)

    def _on_whois(self):
        target = self._require_target()
        if target is None:
            return
        self._set_status(f"WHOIS lookup for {target} ...")

        def task():
            result = self.engine.whois_lookup(target)
            self._last_results = result
            self.post_ui(self._display_whois, result)
            error = result.get("error")
            self.post_ui(
                self._set_status,
                error or "WHOIS lookup complete",
                "error" if error else "success",
            )
            self._save("WHOIS", target, self._last_results)

        self._run_bg(task)

    def _on_zone_transfer(self):
        target = self._require_target()
        if target is None:
            return
        ns = self.dns_server.get() or None
        self._set_status(f"Attempting zone transfer for {target} ...")

        def task():
            result = self.engine.zone_transfer(target, ns)
            self._last_results = result
            self.post_ui(self._display_zone_transfer, result)
            error = result.get("error")
            self.post_ui(
                self._set_status,
                error or "Zone transfer completed",
                "warning" if error else "success",
            )

        self._run_bg(task)


    def _display_dns(self, result):
        self.console.clear()
        self.console.append_line(
            f"  DNS Lookup: {result.query} ({result.record_type})", "header"
        )
        self.console.append_line(
            f"  Server: {result.server}  |  Response: {result.response_time_ms} ms",
            "dim",
        )
        self.console.append_line("")

        if result.error:
            self.console.append_line(f"  Error: {result.error}", "error")
            return

        for rec in result.records:
            line_parts = []
            for k, v in rec.items():
                line_parts.append(f"{k}={v}")
            self.console.append_line("  " + "  |  ".join(line_parts), "success")

        self.console.append_line(f"\n  Total records: {len(result.records)}", "info")

    def _display_multi_dns(self, results):
        self.console.clear()
        self.console.append_line("  All Records Query", "header")
        self.console.append_line("")

        for result in sorted(results, key=lambda r: r.record_type):
            self.console.append_line(f"  [{result.record_type}]", "info")
            if result.error:
                self.console.append_line(f"    {result.error}", "dim")
            else:
                for rec in result.records:
                    self.console.append_line(f"    {rec.get('value', '')}", "success")
            self.console.append_line("")

    def _display_propagation(self, results):
        self.console.clear()
        self.console.append_line("  DNS Propagation Check", "header")
        self.console.append_line("")

        for result in results:
            if result.error:
                self.console.append_line(
                    f"  {result.server:<24}  ERROR: {result.error}", "error"
                )
            else:
                values = ", ".join(r["value"] for r in result.records)
                self.console.append_line(
                    f"  {result.server:<24}  {values:<30}  {result.response_time_ms} ms",
                    "success",
                )

    def _display_whois(self, data):
        self.console.clear()
        self.console.append_line("  WHOIS Lookup", "header")
        self.console.append_line("")

        if data.get("error"):
            self.console.append_line(f"  Error: {data['error']}", "error")
            return

        for key, value in data.items():
            if value and value != "N/A":
                label = key.replace("_", " ").title()
                self.console.append_line(f"  {label:<20}  {value}", "info")

    def _display_zone_transfer(self, data):
        self.console.clear()
        self.console.append_line("  Zone Transfer Attempt", "header")
        self.console.append_line("")

        if data.get("error"):
            self.console.append_line(f"  {data['error']}", "warning")
            self.console.append_line("")
            self.console.append_line(
                "  Note: AXFR (DNS zone transfer) is intentionally disabled on",
                "dim",
            )
            self.console.append_line(
                "  virtually all production name servers. Getting refused here is",
                "dim",
            )
            self.console.append_line(
                "  the expected, secure outcome -- not a tool failure. Open AXFR",
                "dim",
            )
            self.console.append_line(
                "  is itself a misconfiguration finding worth reporting if you see one.",
                "dim",
            )
            return

        self.console.append_line(
            f"  Transfer successful! {data.get('total', 0)} records found.", "success"
        )
        if data.get("nameserver"):
            self.console.append_line(
                f"  Server: {data['nameserver']} (this is a misconfiguration finding)",
                "warning",
            )
        self.console.append_line("")
        for rec in data.get("records", []):
            self.console.append_line(
                f"  {rec['name']:<30}  {rec['type']:<8}  TTL={rec['ttl']:<6}  {rec['value']}"
            )


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
            initialfile=f"netrecon_dns.{ext}",
        )
        if not path:
            return
        try:
            out = fn(self._last_results, path, trusted=True, **kwargs)
        except Exception as e:
            log.exception("DNS export failed (%s)", ext)
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
        self._do_export(ExportEngine.to_html, "html", "HTML", title="DNS Report")

    def _copy(self):
        text = self.console.get_text()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("Copied to clipboard", "success")

    def _clear(self):
        self.console.clear()
        self._last_results = None

    # helpers

    def _set_status(self, msg, level="info"):
        if self.status:
            self.status.set_message(msg, level)

    def _save(self, scan_type, target, data):
        if self.db:
            try:
                self.db.save(scan_type, target, data)
            except Exception:
                log.exception("Failed to save %s to history", scan_type)
