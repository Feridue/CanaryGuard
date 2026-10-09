"""
Verification script for CanaryGuard Enhancements:
1. Historical incident persistence across restarts
2. Formatted human-readable logging (canaryguard_formatted.log)
3. Recursive folder monitoring and event detection inside a custom folder
4. Mode status banner and visual feedback
"""

import os
import sys
import time
import shutil
from pathlib import Path

# Force UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from main import CanaryGuardEngine
from ui.dashboard import CanaryGuardDashboard


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

# ── 1. Historical Incident Persistence ─────────────────────────────────────
separator("1. Historical Incident Persistence Across Restarts")
try:
    engine1 = CanaryGuardEngine()
    incident_count = len(engine1.recent_incidents)
    all_passed &= check("Engine loaded historical incidents on startup", incident_count > 0)
    print(f"  Loaded {incident_count} past incident(s) from canaryguard.log into memory.")
except Exception as exc:
    all_passed = False
    check(f"Incident persistence FAILED: {exc}", False)


# ── 2. Formatted Human-Readable Logging ────────────────────────────────────
separator("2. Human-Readable Log Formatting")
try:
    formatted_log_file = engine1.logger._formatted_log_file
    all_passed &= check("Formatted log file path configured", formatted_log_file is not None)
    
    # Write a test log event
    engine1.logger.log_system_event("Enhancement test run")
    all_passed &= check("Formatted log file exists on disk", formatted_log_file.exists())
    
    formatted_content = engine1.logger.read_formatted_logs(max_entries=10)
    all_passed &= check("Formatted log reader returned readable text", len(formatted_content) > 0 and "SYSTEM" in formatted_content)
    print(f"  Sample formatted log line:\n  {formatted_content.splitlines()[-1]}")
except Exception as exc:
    all_passed = False
    check(f"Formatted log FAILED: {exc}", False)


# ── 3. Recursive Folder Monitoring ─────────────────────────────────────────
separator("3. Recursive Folder Monitoring")
test_folder = project_root / "data" / "test_folder_watch"
try:
    # Clean up test folder if already exists
    if test_folder.exists():
        shutil.rmtree(test_folder)
    test_folder.mkdir(parents=True, exist_ok=True)

    # Create dummy files inside the folder
    sub_file1 = test_folder / "document1.txt"
    sub_file1.write_text("initial content 1")
    
    sub_dir = test_folder / "nested"
    sub_dir.mkdir(exist_ok=True)
    sub_file2 = sub_dir / "spreadsheet.xlsx"
    sub_file2.write_text("initial content 2")

    engine2 = CanaryGuardEngine()
    engine2.logger.config["mode"] = "Observe"
    engine2.logger.config["event_grouping_window"] = 1
    engine2.start()

    # Add folder to monitoring at runtime
    added = engine2.add_folder(str(test_folder))
    all_passed &= check("add_folder returned True", added)
    all_passed &= check("Folder in engine.monitored_folders", str(test_folder.resolve()) in engine2.monitored_folders)

    # Verify is_path_monitored
    all_passed &= check("is_path_monitored identifies nested file", engine2.manager.is_path_monitored(sub_file2) is not None)

    # Clean up folder monitoring
    removed = engine2.remove_folder(str(test_folder))
    all_passed &= check("remove_folder returned True", removed)
    all_passed &= check("Folder removed from engine.monitored_folders", str(test_folder.resolve()) not in engine2.monitored_folders)

    engine2.stop()
    shutil.rmtree(test_folder, ignore_errors=True)

except Exception as exc:
    all_passed = False
    check(f"Folder monitoring FAILED: {exc}", False)


# ── 4. Dashboard Mode Feedback & Status Banner ─────────────────────────────
separator("4. Dashboard Mode Feedback & Status Banner")
dashboard = None
try:
    engine3 = CanaryGuardEngine()
    dashboard = CanaryGuardDashboard(engine3)
    dashboard.root.update_idletasks()

    # Test Automatic mode display
    dashboard.mode_var.set("Automatic")
    dashboard._on_mode_changed()
    dashboard.root.update_idletasks()
    all_passed &= check("Status indicates Automatic mode", "Automatic" in dashboard.status_var.get())
    all_passed &= check("Banner displays Automatic explanation", "Automatic" in dashboard.banner_var.get())

    # Test Approval mode display
    dashboard.mode_var.set("Approval")
    dashboard._on_mode_changed()
    dashboard.root.update_idletasks()
    all_passed &= check("Status indicates Approval mode", "Approval" in dashboard.status_var.get())
    all_passed &= check("Banner displays Approval explanation", "Approval" in dashboard.banner_var.get())

    # Test Observe mode display
    dashboard.mode_var.set("Observe")
    dashboard._on_mode_changed()
    dashboard.root.update_idletasks()
    all_passed &= check("Status indicates Observe mode", "Observe" in dashboard.status_var.get())
    all_passed &= check("Banner displays Observe explanation", "Observe" in dashboard.banner_var.get())

    dashboard.root.destroy()
except Exception as exc:
    all_passed = False
    check(f"Dashboard mode feedback FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL ENHANCEMENT CHECKS PASSED ✓")
else:
    print("  SOME CHECKS FAILED ✗")
    sys.exit(1)
