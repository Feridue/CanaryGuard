"""
Phase 9 verification script.
Tests the UI components: Shield Icon generator, Dashboard GUI, Tray setup, and Registry Autostart.
"""

import os
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from main import CanaryGuardEngine
from ui.tray import create_shield_icon, CanaryGuardTray
from ui.dashboard import CanaryGuardDashboard
from ui.autostart import is_autostart_enabled, set_autostart


def separator(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def check(label: str, result: bool):
    icon = "OK" if result else "XX"
    status = "PASS" if result else "FAIL"
    print(f"  [{icon}] {status}  --  {label}")
    return result


all_passed = True

# ── 1. Shield Icon Generator ───────────────────────────────────────────────
separator("1. Shield Icon Generator")
try:
    icon_img = create_shield_icon(64)
    all_passed &= check("Shield icon created", icon_img is not None)
    all_passed &= check("Icon width is 64", icon_img.size[0] == 64)
    all_passed &= check("Icon height is 64", icon_img.size[1] == 64)
    all_passed &= check("Icon has RGBA channels", icon_img.mode == "RGBA")
except Exception as exc:
    all_passed = False
    check(f"Icon creation FAILED: {exc}", False)


# ── 2. Windows Autostart Registry Management ───────────────────────────────
separator("2. Windows Autostart Registry Management")
try:
    initial_state = is_autostart_enabled()
    # Test setting to True
    set_autostart(True)
    all_passed &= check("Autostart registry key written", is_autostart_enabled())

    # Test setting to False
    set_autostart(False)
    all_passed &= check("Autostart registry key removed", not is_autostart_enabled())

    # Restore initial state
    set_autostart(initial_state)
except Exception as exc:
    all_passed = False
    check(f"Autostart test FAILED: {exc}", False)


# ── 3. Dashboard GUI Initialization & Widgets ──────────────────────────────
separator("3. Dashboard GUI Construction")
engine = None
dashboard = None
try:
    engine = CanaryGuardEngine()
    engine.logger.config["mode"] = "Observe"
    engine.start()

    dashboard = CanaryGuardDashboard(engine)
    dashboard.root.update_idletasks()

    all_passed &= check("Tkinter root window initialized", dashboard.root is not None)
    all_passed &= check("Status label shows MONITORING", "MONITORING" in dashboard.status_var.get())
    all_passed &= check("Mode dropdown initialized to Observe", dashboard.mode_var.get() == "Observe")
    all_passed &= check("Canary listbox populated with decoy files", dashboard.canary_listbox.size() > 0)
    all_passed &= check("Incident Treeview table constructed", dashboard.tree is not None)

    # Test pause toggle via GUI
    dashboard._toggle_pause()
    dashboard.root.update_idletasks()
    all_passed &= check("Pause button switched status to PAUSED", "PAUSED" in dashboard.status_var.get())
    all_passed &= check("Engine is_paused is True", engine.is_paused)

    dashboard._toggle_pause()
    dashboard.root.update_idletasks()
    all_passed &= check("Resume button switched status back to MONITORING", "MONITORING" in dashboard.status_var.get())

except Exception as exc:
    all_passed = False
    check(f"Dashboard initialization FAILED: {exc}", False)


# ── 4. Live Incident Feed in GUI ───────────────────────────────────────────
separator("4. Live Incident Feed in GUI")
try:
    mock_incident = {
        "incident_id": "test-uuid-1234",
        "timestamp": "2026-10-04T12:00:00Z",
        "logged_at": "2026-10-04T12:00:00Z",
        "files_affected_count": 2,
        "affected_canaries": [
            {"canary_name": "passwords_backup.txt", "state": "modified"},
            {"canary_name": "tax_return_2025.pdf", "state": "deleted"}
        ],
        "decision": "observe",
        "action_taken": "none",
        "candidates": [
            {
                "name": "malicious_ransom.exe",
                "pid": 8844,
                "confidence": "High",
                "explanation": "Massive I/O burst delta 45.2 MB"
            }
        ]
    }

    # Dispatch to dashboard
    dashboard._insert_incident_row(mock_incident)
    dashboard.root.update_idletasks()

    children = dashboard.tree.get_children()
    all_passed &= check("Row inserted into incident Treeview", len(children) >= 1)

    if children:
        top_row = dashboard.tree.item(children[0])
        vals = top_row["values"]
        all_passed &= check("Row contains affected canaries", "passwords_backup.txt" in str(vals))
        all_passed &= check("Row contains suspect process name", "malicious_ransom.exe" in str(vals))
        all_passed &= check("Row contains confidence level", "High" in str(vals))

except Exception as exc:
    all_passed = False
    check(f"Live incident feed FAILED: {exc}", False)


# ── 5. System Tray Construction ────────────────────────────────────────────
separator("5. System Tray Setup")
try:
    tray = CanaryGuardTray(engine, dashboard)
    all_passed &= check("CanaryGuardTray instantiated", tray is not None)
    all_passed &= check("Tray icon has menu items", tray._get_menu() is not None)
except Exception as exc:
    all_passed = False
    check(f"Tray setup FAILED: {exc}", False)


# ── Cleanup ────────────────────────────────────────────────────────────────
try:
    if dashboard and dashboard.root:
        dashboard.root.destroy()
    if engine:
        engine.stop()
except Exception:
    pass


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 9 & 10 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
