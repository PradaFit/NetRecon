"""Scan History tab"""

import json
import threading
from tkinter import filedialog, messagebox
import customtkinter as ctk

from .theme import COLORS, FONT_FAMILY, FONT_MONO
from .widgets import OutputConsole
from netrecon import DatabaseManager, ExportEngine


class HistoryTab(ctk.CTkFrame):

    def __init__(self, master, status_bar=None, db=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status_bar
        self.db = db or DatabaseManager()
        self._selected_id = None
        self._build_ui()
        self.after(200, self._refresh)

    def _build_ui(self):
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=10, pady=(10, 4))

        self.search_entry = ctk.CTkEntry(
            toolbar,
            width=250,
            height=32,
            placeholder_text="Search targets ...",
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            corner_radius=6,
        )
        self.search_entry.pack(side="left", padx=(0, 8))
        self.search_entry.bind("<Return>", lambda e: self._refresh())

        self.filter_var = ctk.StringVar(value="All Types")
        self.filter_menu = ctk.CTkOptionMenu(
            toolbar,
            values=[
                "All Types",
                "DNS Resolve",
                "DNS Reverse",
                "DNS All Records",
                "DNS Propagation",
                "WHOIS",
                "Port Scan",
                "Geolocation",
                "Traceroute Geo",
            ],
            variable=self.filter_var,
            width=160,
            height=32,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["bg_input"],
            button_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["bg_card"],
            dropdown_text_color=COLORS["text"],
            corner_radius=6,
            command=lambda _: self._refresh(),
        )
        self.filter_menu.pack(side="left", padx=(0, 8))

        btn_cfg = {
            "height": 32,
            "corner_radius": 6,
            "font": (FONT_FAMILY, 12),
            "fg_color": COLORS["bg_input"],
            "hover_color": COLORS["accent_dim"],
            "text_color": COLORS["text"],
            "border_width": 1,
            "border_color": COLORS["border"],
        }

        ctk.CTkButton(
            toolbar, text="Refresh", command=self._refresh, width=80, **btn_cfg
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            toolbar, text="Delete", command=self._delete, width=80, **btn_cfg
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            toolbar, text="Export All", command=self._export_all, width=90, **btn_cfg
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            toolbar,
            text="Clear All",
            command=self._clear_all,
            width=90,
            fg_color="#4d0d0d",
            hover_color="#6d1d1d",
            height=32,
            corner_radius=6,
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text"],
        ).pack(side="left", padx=(0, 4))

        # stats bar
        self._stats_label = ctk.CTkLabel(
            self,
            text="",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._stats_label.pack(fill="x", padx=14, pady=(2, 2))

        # paned view: list + detail

        pane = ctk.CTkFrame(self, fg_color="transparent")
        pane.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_columnconfigure(1, weight=2)
        pane.grid_rowconfigure(0, weight=1)

        # Left: history list
        self._list_frame = ctk.CTkScrollableFrame(
            pane,
            fg_color=COLORS["bg_card"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        # Right: detail view
        self.detail = OutputConsole(pane)
        self.detail.grid(row=0, column=1, sticky="nsew")

    # data loading

    def _refresh(self, *_):
        search = self.search_entry.get().strip() or None
        ftype = self.filter_var.get()
        scan_type = None if ftype == "All Types" else ftype

        records = self.db.get_history(limit=200, scan_type=scan_type, search=search)
        stats = self.db.get_stats()

        self._stats_label.configure(
            text=f"Total scans: {stats['total_scans']}    |    "
            + "    ".join(f"{k}: {v}" for k, v in stats.get("by_type", {}).items())
        )

        # Clear list
        for w in self._list_frame.winfo_children():
            w.destroy()

        if not records:
            ctk.CTkLabel(
                self._list_frame,
                text="No scan history found.",
                font=(FONT_FAMILY, 12),
                text_color=COLORS["text_dim"],
            ).pack(pady=20)
            return

        for rec in records:
            self._add_list_item(rec)

    def _add_list_item(self, rec):
        row = ctk.CTkFrame(
            self._list_frame,
            fg_color=COLORS["bg_dark"],
            corner_radius=6,
            height=52,
            cursor="hand2",
        )
        row.pack(fill="x", pady=2, padx=4)
        row.pack_propagate(False)

        type_colors = {
            "DNS": COLORS["accent"],
            "Nmap": COLORS["warning"],
            "Geo": COLORS["success"],
            "WHOIS": "#aa88ff",
            "Traceroute": "#ff88aa",
        }
        color = COLORS["text_dim"]
        for prefix, c in type_colors.items():
            if rec["scan_type"].startswith(prefix):
                color = c
                break

        indicator = ctk.CTkFrame(row, fg_color=color, width=4, corner_radius=2)
        indicator.pack(side="left", fill="y", padx=(4, 8), pady=6)

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, pady=4)

        ctk.CTkLabel(
            info,
            text=f"{rec['scan_type']}  -  {rec['target']}",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).pack(anchor="w")

        ts = rec.get("timestamp", "")[:19].replace("T", "  ")
        summary = rec.get("summary", "") or ""
        ctk.CTkLabel(
            info,
            text=f"{ts}    {summary}",
            font=(FONT_FAMILY, 10),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).pack(anchor="w")

        scan_id = rec["id"]
        row.bind("<Button-1>", lambda e, sid=scan_id: self._show_detail(sid))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, sid=scan_id: self._show_detail(sid))
            for grandchild in child.winfo_children():
                grandchild.bind(
                    "<Button-1>", lambda e, sid=scan_id: self._show_detail(sid)
                )

    def _show_detail(self, scan_id):
        self._selected_id = scan_id
        record = self.db.get_detail(scan_id)
        if not record:
            return

        self.detail.clear()
        self.detail.append_line(
            f"  Scan #{scan_id}  -  {record['scan_type']}", "header"
        )
        self.detail.append_line(f"  Target: {record['target']}", "info")
        self.detail.append_line(f"  Time:   {record['timestamp']}", "dim")
        if record.get("summary"):
            self.detail.append_line(f"  Summary: {record['summary']}", "dim")
        self.detail.append_line("")
        self.detail.append_line(
            json.dumps(record["result_data"], indent=2, default=str), "dim"
        )


    def _delete(self):
        if self._selected_id is None:
            return
        self.db.delete(self._selected_id)
        self._selected_id = None
        self.detail.clear()
        self._refresh()
        self._set_status("Scan deleted", "success")

    def _clear_all(self):
        if messagebox.askyesno("Clear History", "Delete all scan history?"):
            self.db.clear()
            self._refresh()
            self.detail.clear()
            self._set_status("History cleared", "success")

    def _export_all(self):
        records = self.db.get_history(limit=10000)
        if not records:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile="netrecon_history.json",
        )
        if path:
            ExportEngine.to_json(records, path)
            self._set_status(f"History exported to {path}", "success")

    def _set_status(self, msg, level="info"):
        if self.status:
            self.status.set_message(msg, level)
