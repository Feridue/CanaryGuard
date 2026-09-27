"""
Phase 2 verification script.
Tests the Test Simulator's behavior and reversibility.
"""

import sys
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

# ── 0. Setup & Planting ───────────────────────────────────────────────────
separator("0. Setup & Planting Canaries")
try:
    logger = EvidenceLogger()
    manager = CanaryManager(logger)
    
    # Ensure a clean slate
    manager.plant_canaries()
    
    all_passed &= check("Canary files planted", len(list(manager.protected_dir.iterdir())) > 0)
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Run Simulator ──────────────────────────────────────────────────────
separator("1. Run Simulator")
try:
    sim = RansomwareSimulator()
    files_affected = sim.run()
    
    all_passed &= check("Simulator executed successfully", True)
    all_passed &= check(f"Files affected > 0 ({files_affected})", files_affected > 0)
except Exception as exc:
    all_passed = False
    check(f"Simulator run FAILED: {exc}", False)


# ── 2. Verify Effects ─────────────────────────────────────────────────────
separator("2. Verify Simulator Effects")
try:
    dir_contents = list(manager.protected_dir.iterdir())
    
    locked_files = [f for f in dir_contents if f.suffix == ".locked"]
    note_exists = any(f.name == "RANSOM_NOTE.txt" for f in dir_contents)
    original_canaries_exist = any(f.name in manager.canary_filenames for f in dir_contents)
    
    all_passed &= check("Original files are missing", not original_canaries_exist)
    all_passed &= check("Files renamed to .locked", len(locked_files) > 0)
    all_passed &= check("Ransom note dropped", note_exists)
    
    # Verify content of a locked file
    if locked_files:
        with open(locked_files[0], "rb") as f:
            content = f.read()
        all_passed &= check("File content overwritten", b"ENCRYPTED_BY_SIMULATOR" in content)
except Exception as exc:
    all_passed = False
    check(f"Effects verification FAILED: {exc}", False)


# ── 3. Verify Reversibility ───────────────────────────────────────────────
separator("3. Verify Reversibility")
try:
    # Re-plant canaries to overwrite/restore
    # First, clean up the locked files and note (simulating operator cleanup)
    for filepath in manager.protected_dir.iterdir():
        if filepath.is_file():
            filepath.unlink()
            
    # Now restore baseline
    manager.plant_canaries()
    
    dir_contents = list(manager.protected_dir.iterdir())
    locked_files = [f for f in dir_contents if f.suffix == ".locked"]
    note_exists = any(f.name == "RANSOM_NOTE.txt" for f in dir_contents)
    
    # Check that canaries are unchanged according to the manager
    verify_results = [manager.verify_canary(c) == "unchanged" for c in manager.canary_filenames]
    
    all_passed &= check("Locked files removed", len(locked_files) == 0)
    all_passed &= check("Ransom note removed", not note_exists)
    all_passed &= check("All canaries restored to baseline", all(verify_results))
except Exception as exc:
    all_passed = False
    check(f"Reversibility check FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 2 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
