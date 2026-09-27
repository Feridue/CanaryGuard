"""
Phase 3 verification script.
Tests the watchdog filesystem monitor, grouping window, and filtering.
"""

import os
import sys
import threading
import time
from pathlib import Path

# Force UTF-8 output on Windows so test symbols print correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Make sure imports resolve from the project root
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from evidence.logger import EvidenceLogger
from canary.manager import CanaryManager
from monitoring.filesystem import FilesystemMonitor
from simulator.ransom_sim import RansomwareSimulator


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
emitted_incidents = []

def incident_callback(incident_data):
    """Callback for the filesystem monitor."""
    emitted_incidents.append(incident_data)


# ── 0. Setup & Planting ───────────────────────────────────────────────────
separator("0. Setup Monitor & Planting Canaries")
try:
    logger = EvidenceLogger()
    manager = CanaryManager(logger)
    
    # We will temporarily shorten the grouping window for this test to 1 second 
    # to avoid waiting too long during test execution.
    logger.config["event_grouping_window"] = 1
    
    # Ensure a clean slate
    manager.plant_canaries()
    
    monitor = FilesystemMonitor(manager, logger, incident_callback)
    monitor.start()
    
    all_passed &= check("Monitor started in background", monitor.observer.is_alive())
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Single Event Verification ──────────────────────────────────────────
separator("1. Verify Single Canary Event")
try:
    emitted_incidents.clear()
    
    # Edit a single canary file
    canary_to_edit = manager.canary_filenames[0]
    canary_path = manager.protected_dir / canary_to_edit
    
    with open(canary_path, "a") as f:
        f.write("test_edit")
        
    print("  Waiting for grouping window to close (1.5s)...")
    time.sleep(1.5)
    
    all_passed &= check("Exactly one incident generated", len(emitted_incidents) == 1)
    
    if emitted_incidents:
        inc = emitted_incidents[0]
        all_passed &= check("Incident contains exactly 1 affected canary", inc["files_affected_count"] == 1)
        all_passed &= check(f"Affected canary is {canary_to_edit}", inc["affected_canaries"][0]["canary_name"] == canary_to_edit)
        all_passed &= check("Canary state classified as 'modified'", inc["affected_canaries"][0]["state"] == "modified")
except Exception as exc:
    all_passed = False
    check(f"Single event verification FAILED: {exc}", False)


# ── 2. Filtering Verification ─────────────────────────────────────────────
separator("2. Verify Noise Filtering (Non-Canary File)")
try:
    emitted_incidents.clear()
    
    # Create and modify a non-canary file
    noise_path = manager.protected_dir / "legit_user_file.txt"
    with open(noise_path, "w") as f:
        f.write("hello world")
        
    print("  Waiting for grouping window to close (1.5s)...")
    time.sleep(1.5)
    
    all_passed &= check("Zero incidents generated from non-canary file", len(emitted_incidents) == 0)
    
    # Cleanup noise file
    noise_path.unlink()
except Exception as exc:
    all_passed = False
    check(f"Filtering verification FAILED: {exc}", False)


# ── 3. Simulator Grouping Verification ────────────────────────────────────
separator("3. Verify Rapid Simulator Events (Grouping)")
try:
    emitted_incidents.clear()
    
    # To test grouping, we must first reset the canaries because one was modified in step 1
    # We briefly stop the monitor so it doesn't trigger on the replanting
    monitor.stop()
    manager.plant_canaries()
    
    monitor = FilesystemMonitor(manager, logger, incident_callback)
    monitor.start()
    
    # Run the rapid simulator
    sim = RansomwareSimulator()
    print("  Running simulator...")
    
    # Suppress simulator stdout for cleaner test output
    old_stdout = sys.stdout
    sys.stdout = open(os.devnull, "w")
    expected_count = sim.run()
    sys.stdout = old_stdout
    
    print("  Waiting for grouping window to close (1.5s)...")
    time.sleep(1.5)
    
    all_passed &= check("Exactly one incident generated for full burst", len(emitted_incidents) == 1)
    
    if emitted_incidents:
        inc = emitted_incidents[0]
        
        # Verify the number of affected canaries matches what the simulator touched
        # Note: The simulator drops RANSOM_NOTE.txt which is ignored, and touches 8 canaries
        # so expected_count includes 8 locked files + note, but the monitor should only report 8
        canary_count = len(manager.canary_filenames)
        all_passed &= check(f"Incident groups {canary_count} files correctly", inc["files_affected_count"] == canary_count)
        
        # Verify state is classified as 'renamed' or 'extension-changed' since simulator renames them
        if inc["affected_canaries"]:
            sample_state = inc["affected_canaries"][0]["state"]
            all_passed &= check(f"State properly classified (e.g. {sample_state})", sample_state in ["renamed", "extension-changed", "modified", "deleted"])

except Exception as exc:
    all_passed = False
    check(f"Simulator grouping verification FAILED: {exc}", False)
finally:
    if monitor:
        monitor.stop()


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 3 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
