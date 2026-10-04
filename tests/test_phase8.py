"""
Phase 8 end-to-end verification script.
Starts the full engine, runs the simulator, and checks the complete pipeline fires.
"""

import os
import sys
import time
import threading
from pathlib import Path

# Force UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from main import CanaryGuardEngine
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
received_incidents = []

def gui_callback(incident):
    """Simulates what the GUI would receive."""
    received_incidents.append(incident)


# ── 0. Setup ──────────────────────────────────────────────────────────────
separator("0. Engine Startup")
try:
    engine = CanaryGuardEngine()

    # Force Observe mode so no real suspensions happen during the test
    engine.logger.config["mode"] = "Observe"
    # Shorten grouping window for faster test
    engine.logger.config["event_grouping_window"] = 1

    # Wire up the GUI callback
    engine.on_incident_callback = gui_callback

    engine.start()
    time.sleep(0.5)  # allow threads to initialise

    all_passed &= check("Engine started", engine.is_running)
    all_passed &= check("Not paused", not engine.is_paused)
    all_passed &= check("Mode is Observe", engine.mode == "Observe")
    all_passed &= check(f"Canaries planted ({len(engine.canary_files)})", len(engine.canary_files) > 0)

except Exception as exc:
    all_passed = False
    check(f"Startup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Run Simulator ──────────────────────────────────────────────────────
separator("1. Run Ransomware Simulator")
try:
    received_incidents.clear()
    print("  Running simulator against protected directory...")

    sim = RansomwareSimulator()
    old_stdout = sys.stdout
    sys.stdout = open(os.devnull, "w")
    sim.run()
    sys.stdout = old_stdout

    print("  Waiting for grouping window + pipeline (6s)...")
    time.sleep(6)

    all_passed &= check("At least one incident fired", len(received_incidents) >= 1)

except Exception as exc:
    all_passed = False
    check(f"Simulator run FAILED: {exc}", False)


# ── 2. Verify Incident Structure ───────────────────────────────────────────
separator("2. Verify Incident Pipeline Output")
try:
    if received_incidents:
        inc = received_incidents[0]
        all_passed &= check("Has 'incident_id'",          bool(inc.get("incident_id")))
        all_passed &= check("Has 'logged_at'",            bool(inc.get("logged_at")))
        all_passed &= check("Has 'candidates' list",      isinstance(inc.get("candidates"), list))
        all_passed &= check("Has 'decision'",             bool(inc.get("decision")))
        all_passed &= check("Has 'action_taken'",         bool(inc.get("action_taken")))
        all_passed &= check("Decision is 'observe'",      inc.get("decision") == "observe")
        all_passed &= check("Action is 'none'",           inc.get("action_taken") == "none")
        all_passed &= check("Incident in recent_incidents", len(engine.recent_incidents) >= 1)

        if inc.get("candidates"):
            cand = inc["candidates"][0]
            all_passed &= check("Candidate has 'confidence'",  bool(cand.get("confidence")))
            all_passed &= check("Candidate has 'explanation'", bool(cand.get("explanation")))
            print(f"\n  Top candidate: {cand.get('name')} — {cand.get('confidence')} confidence")
            print(f"  Evidence: {cand.get('explanation')}")
    else:
        all_passed = False
        check("No incidents received — pipeline did not fire", False)

except Exception as exc:
    all_passed = False
    check(f"Verification FAILED: {exc}", False)


# ── 3. Runtime Canary Management ───────────────────────────────────────────
separator("3. Runtime Canary Add / Remove")
try:
    # Restore canaries first (simulator locked them)
    for f in engine.manager.protected_dir.iterdir():
        if f.is_file():
            f.unlink()
    engine.manager.plant_canaries()

    before_count = len(engine.canary_files)

    # Create a temp test file to add
    temp_path = engine.manager.protected_dir / "temp_test_canary.txt"
    temp_path.write_text("temp content")

    added = engine.add_canary(str(temp_path))
    all_passed &= check("add_canary returned True", added)
    all_passed &= check("Canary count increased by 1", len(engine.canary_files) == before_count + 1)

    removed = engine.remove_canary("temp_test_canary.txt")
    all_passed &= check("remove_canary returned True", removed)
    all_passed &= check("Canary count restored", len(engine.canary_files) == before_count)

except Exception as exc:
    all_passed = False
    check(f"Canary management FAILED: {exc}", False)


# ── 4. Pause / Resume ─────────────────────────────────────────────────────
separator("4. Pause / Resume Controls")
try:
    engine.pause()
    all_passed &= check("Engine paused", engine.is_paused)

    engine.resume()
    all_passed &= check("Engine resumed", not engine.is_paused)

except Exception as exc:
    all_passed = False
    check(f"Pause/Resume FAILED: {exc}", False)


# ── 5. Stop ───────────────────────────────────────────────────────────────
separator("5. Clean Shutdown")
try:
    engine.stop()
    all_passed &= check("Engine stopped", not engine.is_running)

except Exception as exc:
    all_passed = False
    check(f"Shutdown FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 8 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
