"""
CanaryGuard — Phase 9b: Tkinter Dashboard GUI
Provides a desktop control center to monitor incidents, manage canary decoy files,
and adjust settings live.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from pathlib import Path
from typing import Optional

from ui.autostart import is_autostart_enabled, set_autostart


class CanaryGuardDashboard:
    def __init__(self, engine, on_quit_callback=None):
        self.engine = engine
        self.on_quit_callback = on_quit_callback

        self.root = tk.Tk()
        self.root.title("CanaryGuard — Ransomware Shield")
        self.root.geometry("820x620")
        self.root.minsize(700, 500)

        # Style configuration
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Intercept window close button (X) to hide instead of quit
        self.root.protocol("WM_DELETE_WINDOW", self.hide)

        # Register callback with engine so live incidents populate GUI
        self.engine.on_incident_callback = self._on_incident_received

        self._build_ui()
        self._refresh_all()

    def _build_ui(self):
        # ── Top Header / Status Bar ─────────────────────────────────────────
        header_frame = ttk.Frame(self.root, padding=12)
        header_frame.pack(fill=tk.X)

        title_label = ttk.Label(
            header_frame,
            text="🛡️ CanaryGuard Protection Center",
            font=("Segoe UI", 14, "bold")
        )
        title_label.pack(side=tk.LEFT)

        # Right-aligned controls
        ctrl_frame = ttk.Frame(header_frame)
        ctrl_frame.pack(side=tk.RIGHT)

        self.status_var = tk.StringVar(value="🟢 MONITORING")
        self.status_label = ttk.Label(
            ctrl_frame,
            textvariable=self.status_var,
            font=("Segoe UI", 10, "bold"),
            padding=(8, 4)
        )
        self.status_label.pack(side=tk.LEFT, padx=6)

        self.pause_btn = ttk.Button(
            ctrl_frame,
            text="Pause",
            command=self._toggle_pause,
            width=8
        )
        self.pause_btn.pack(side=tk.LEFT, padx=4)

        ttk.Label(ctrl_frame, text="Mode:").pack(side=tk.LEFT, padx=(10, 2))
        self.mode_var = tk.StringVar(value=self.engine.mode)
        self.mode_combo = ttk.Combobox(
            ctrl_frame,
            textvariable=self.mode_var,
            values=["Observe", "Approval", "Automatic"],
            state="readonly",
            width=10
        )
        self.mode_combo.pack(side=tk.LEFT, padx=4)
        self.mode_combo.bind("<<ComboboxSelected>>", self._on_mode_changed)

        # Separator
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10)

        # ── Notebook / Tabs ─────────────────────────────────────────────────
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Tab 1: Live Incident Feed
        self.incident_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.incident_tab, text="🚨 Incident Feed")
        self._build_incident_tab()

        # Tab 2: Canary Decoy Files
        self.canary_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.canary_tab, text="📁 Canary Files")
        self._build_canary_tab()

        # Tab 3: Settings & Logs
        self.settings_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.settings_tab, text="⚙️ Settings")
        self._build_settings_tab()

    # ── Tab 1: Incident Feed ────────────────────────────────────────────────
    def _build_incident_tab(self):
        # Table frame
        tree_frame = ttk.Frame(self.incident_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("time", "canaries", "suspect", "confidence", "action")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        self.tree.heading("time", text="Time (UTC)")
        self.tree.heading("canaries", text="Affected Files")
        self.tree.heading("suspect", text="Suspected Process")
        self.tree.heading("confidence", text="Confidence")
        self.tree.heading("action", text="Action Taken")

        self.tree.column("time", width=140, anchor=tk.CENTER)
        self.tree.column("canaries", width=160)
        self.tree.column("suspect", width=180)
        self.tree.column("confidence", width=100, anchor=tk.CENTER)
        self.tree.column("action", width=110, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_incident_selected)

        # Tag configurations for colors
        self.tree.tag_configure("HIGH", background="#ffcccc")
        self.tree.tag_configure("MEDIUM", background="#fff2cc")
        self.tree.tag_configure("LOW", background="#e6f2ff")

        # Details box below
        detail_frame = ttk.LabelFrame(self.incident_tab, text="Incident Forensic Evidence", padding=6)
        detail_frame.pack(fill=tk.X, pady=(6, 0))

        self.detail_text = tk.Text(detail_frame, height=5, wrap=tk.WORD, font=("Consolas", 9))
        self.detail_text.pack(fill=tk.X)
        self.detail_text.insert(tk.END, "Select an incident above to inspect forensic correlation and evidence details.")
        self.detail_text.configure(state="disabled")

    # ── Tab 2: Canary Files ─────────────────────────────────────────────────
    def _build_canary_tab(self):
        # Path info
        path_box = ttk.LabelFrame(self.canary_tab, text="Protected Sandbox Folder", padding=8)
        path_box.pack(fill=tk.X, pady=(0, 8))

        dir_path = str(self.engine.manager.protected_dir)
        ttk.Label(path_box, text=dir_path, font=("Consolas", 9)).pack(side=tk.LEFT, padx=4)
        ttk.Button(path_box, text="Open Folder", command=self._open_sandbox_dir).pack(side=tk.RIGHT)

        # File list with buttons
        list_frame = ttk.LabelFrame(self.canary_tab, text="Currently Monitored Decoy Files", padding=8)
        list_frame.pack(fill=tk.BOTH, expand=True)

        content_frame = ttk.Frame(list_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        self.canary_listbox = tk.Listbox(content_frame, font=("Segoe UI", 10), height=10)
        canary_scroll = ttk.Scrollbar(content_frame, orient=tk.VERTICAL, command=self.canary_listbox.yview)
        self.canary_listbox.configure(yscrollcommand=canary_scroll.set)

        self.canary_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canary_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Button row
        btn_row = ttk.Frame(list_frame, padding=(0, 8, 0, 0))
        btn_row.pack(fill=tk.X)

        ttk.Button(btn_row, text="➕ Add Canary File...", command=self._add_canary_dialog).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="🗑️ Remove Selected", command=self._remove_selected_canary).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="🔄 Reset & Replant Baseline", command=self._replant_canaries).pack(side=tk.RIGHT, padx=4)

    # ── Tab 3: Settings ─────────────────────────────────────────────────────
    def _build_settings_tab(self):
        settings_box = ttk.LabelFrame(self.settings_tab, text="System & Startup Preferences", padding=12)
        settings_box.pack(fill=tk.X, pady=6)

        self.autostart_var = tk.BooleanVar(value=is_autostart_enabled())
        autostart_check = ttk.Checkbutton(
            settings_box,
            text="Launch CanaryGuard silently on Windows startup (system tray)",
            variable=self.autostart_var,
            command=self._on_autostart_toggled
        )
        autostart_check.pack(anchor=tk.W, pady=4)

        # Safety & allowlist summary
        allow_box = ttk.LabelFrame(self.settings_tab, text="Whitelisted Critical OS Processes (Never Suspended)", padding=8)
        allow_box.pack(fill=tk.BOTH, expand=True, pady=6)

        allow_list = ", ".join(self.engine.responder.allowlist)
        allow_text = tk.Text(allow_box, height=4, wrap=tk.WORD, font=("Consolas", 9))
        allow_text.pack(fill=tk.BOTH, expand=True)
        allow_text.insert(tk.END, allow_list)
        allow_text.configure(state="disabled")

        # Bottom actions
        action_row = ttk.Frame(self.settings_tab)
        action_row.pack(fill=tk.X, pady=8)

        ttk.Button(action_row, text="Open Evidence Log Directory", command=self._open_log_dir).pack(side=tk.LEFT, padx=4)
        ttk.Button(action_row, text="Quit CanaryGuard Completely", command=self._quit_app).pack(side=tk.RIGHT, padx=4)

    # ── Event handlers & UI Logic ───────────────────────────────────────────

    def _toggle_pause(self):
        if self.engine.is_paused:
            self.engine.resume()
            self.status_var.set("🟢 MONITORING")
            self.pause_btn.configure(text="Pause")
        else:
            self.engine.pause()
            self.status_var.set("🟡 PAUSED")
            self.pause_btn.configure(text="Resume")

    def _on_mode_changed(self, event=None):
        new_mode = self.mode_var.get()
        try:
            self.engine.set_mode(new_mode)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to switch mode: {e}")

    def _on_autostart_toggled(self):
        enable = self.autostart_var.get()
        success = set_autostart(enable)
        if not success:
            messagebox.showwarning("Registry Notice", "Could not update Windows startup registry.")
            self.autostart_var.set(is_autostart_enabled())

    def _add_canary_dialog(self):
        chosen_file = filedialog.askopenfilename(
            title="Select File to Monitor as Canary",
            initialdir=str(Path.home()),
            filetypes=[("Documents & Data", "*.docx *.xlsx *.pdf *.txt *.zip"), ("All Files", "*.*")]
        )
        if chosen_file:
            success = self.engine.add_canary(chosen_file)
            if success:
                self._refresh_canary_list()
                messagebox.showinfo("Success", f"File '{Path(chosen_file).name}' added to protected canary list.")
            else:
                messagebox.showwarning("Notice", "This file is already monitored as a canary.")

    def _remove_selected_canary(self):
        selected_idx = self.canary_listbox.curselection()
        if not selected_idx:
            messagebox.showinfo("Select File", "Please select a canary file to remove.")
            return

        filename = self.canary_listbox.get(selected_idx[0])
        confirm = messagebox.askyesno("Confirm Removal", f"Stop monitoring '{filename}'?\n(The file itself will not be deleted)")
        if confirm:
            self.engine.remove_canary(filename)
            self._refresh_canary_list()

    def _replant_canaries(self):
        confirm = messagebox.askyesno("Replant Baselines", "Replant all original decoy canaries and reset file baselines?")
        if confirm:
            self.engine.manager.plant_canaries()
            self._refresh_canary_list()
            messagebox.showinfo("Reset", "Canary files successfully planted and baselines recorded.")

    def _open_sandbox_dir(self):
        path = str(self.engine.manager.protected_dir)
        os.startfile(path)

    def _open_log_dir(self):
        path = str(self.engine.logger._log_dir)
        os.startfile(path)

    def _refresh_canary_list(self):
        self.canary_listbox.delete(0, tk.END)
        for fname in self.engine.canary_files:
            self.canary_listbox.insert(tk.END, fname)

    def _refresh_all(self):
        self._refresh_canary_list()
        # Load any existing incidents
        for inc in reversed(self.engine.recent_incidents):
            self._insert_incident_row(inc)

    def _on_incident_received(self, incident: dict):
        """Thread-safe UI update when an incident occurs."""
        self.root.after(0, self._insert_incident_row, incident)

    def _insert_incident_row(self, inc: dict):
        # Format timestamp
        ts_raw = inc.get("logged_at") or inc.get("timestamp") or ""
        try:
            dt = datetime.fromisoformat(ts_raw)
            ts = dt.strftime("%H:%M:%S")
        except Exception:
            ts = ts_raw[:8]

        # Extract primary canary
        canary_names = [c.get("canary_name", "") for c in inc.get("affected_canaries", [])]
        canary_str = ", ".join(canary_names) if canary_names else "Unknown"

        # Suspect info
        candidates = inc.get("candidates", [])
        top = candidates[0] if candidates else {}
        suspect = f"{top.get('name', 'None')} (PID {top.get('pid', '-')})" if top else "Unattributed"
        conf = top.get("confidence", "None")
        action = inc.get("action_taken", "none").capitalize()

        tag = conf.upper() if conf in ("High", "Medium", "Low") else ""
        item_id = self.tree.insert("", 0, values=(ts, canary_str, suspect, conf, action), tags=(tag,))
        # Store full incident dict in tree item dictionary
        self.tree.set(item_id, column="time", value=ts)
        self._cached_incidents = getattr(self, "_cached_incidents", {})
        self._cached_incidents[item_id] = inc

    def _on_incident_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        item_id = selected[0]
        inc = getattr(self, "_cached_incidents", {}).get(item_id)
        if not inc:
            return

        candidates = inc.get("candidates", [])
        top = candidates[0] if candidates else {}

        details = []
        details.append(f"Incident ID: {inc.get('incident_id', 'N/A')}")
        details.append(f"Decision: {inc.get('decision', 'N/A')}  |  Action Taken: {inc.get('action_taken', 'N/A')}")
        details.append(f"Files Affected: {inc.get('files_affected_count', 0)}")
        if top:
            details.append(f"Suspect: {top.get('name')} (PID: {top.get('pid')}) | Confidence: {top.get('confidence')}")
            details.append(f"Evidence: {top.get('explanation', 'None recorded')}")
        else:
            details.append("No active candidate identified above threshold.")

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(details))
        self.detail_text.configure(state="disabled")

    def show(self):
        """Bring the dashboard window to front."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def hide(self):
        """Minimize/withdraw the window to system tray."""
        self.root.withdraw()

    def _quit_app(self):
        confirm = messagebox.askyesno("Quit CanaryGuard", "Are you sure you want to stop CanaryGuard and exit completely?")
        if confirm:
            if self.on_quit_callback:
                self.on_quit_callback()
            else:
                self.engine.stop()
                self.root.destroy()
                sys.exit(0)
