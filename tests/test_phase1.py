"""
Phase 1 verification script.
Tests the Canary Manager's ability to plant, hash, and verify files.
"""

import os
import shutil
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

# ── 0. Setup ──────────────────────────────────────────────────────────────
separator("0. Setup")
try:
    logger = EvidenceLogger()
    manager = CanaryManager(logger)
    protected_dir = manager.protected_dir
    
    # Clean up protected dir if it exists to ensure clean state
    if protected_dir.exists():
        shutil.rmtree(protected_dir)
        
    all_passed &= check("Logger and CanaryManager initialized", True)
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Planting Canaries ──────────────────────────────────────────────────
separator("1. Planting Canaries")
try:
    manager.plant_canaries()
    all_passed &= check("plant_canaries completed without errors", True)
    
    all_passed &= check("Protected directory created", protected_dir.exists())
    
    files_created = list(protected_dir.iterdir())
    expected_count = len(manager.canary_filenames)
    all_passed &= check(f"Generated {len(files_created)} files (expected {expected_count})", 
                        len(files_created) == expected_count)
                        
    all_passed &= check("Baselines recorded in memory", len(manager.baselines) == expected_count)
    
    # Verify metadata
    first_canary = manager.canary_filenames[0]
    baseline = manager.baselines[first_canary]
    all_passed &= check("Baseline has size", "size" in baseline and baseline["size"] > 0)
    all_passed &= check("Baseline has hash", "hash" in baseline and len(baseline["hash"]) == 64)
    all_passed &= check("Baseline has mtime", "mtime" in baseline)
    
except Exception as exc:
    all_passed = False
    check(f"Planting FAILED: {exc}", False)


# ── 2. Verification (Unchanged) ───────────────────────────────────────────
separator("2. Verify Unchanged")
try:
    first_canary = manager.canary_filenames[0]
    status = manager.verify_canary(first_canary)
    all_passed &= check(f"Unchanged file verified as '{status}'", status == "unchanged")
except Exception as exc:
    all_passed = False
    check(f"Verification FAILED: {exc}", False)


# ── 3. Verification (Modified) ────────────────────────────────────────────
separator("3. Verify Modified")
try:
    mod_canary = manager.canary_filenames[1]
    mod_path = manager.protected_dir / mod_canary
    
    # Modify it
    with open(mod_path, "a") as f:
        f.write("ransomware_garbage")
        
    status = manager.verify_canary(mod_canary)
    all_passed &= check(f"Modified file verified as '{status}'", status == "modified")
except Exception as exc:
    all_passed = False
    check(f"Modification check FAILED: {exc}", False)


# ── 4. Verification (Renamed) ─────────────────────────────────────────────
separator("4. Verify Renamed")
try:
    renamed_original = manager.canary_filenames[2]
    original_path = manager.protected_dir / renamed_original
    
    # Rename it (same extension)
    new_name = "renamed_" + renamed_original
    new_path = manager.protected_dir / new_name
    original_path.rename(new_path)
    
    status = manager.verify_canary(renamed_original, current_path=new_path)
    all_passed &= check(f"Renamed file verified as '{status}'", status == "renamed")
except Exception as exc:
    all_passed = False
    check(f"Rename check FAILED: {exc}", False)


# ── 5. Verification (Extension Changed) ───────────────────────────────────
separator("5. Verify Extension Changed")
try:
    ext_original = manager.canary_filenames[3]
    original_path = manager.protected_dir / ext_original
    
    # Change extension
    new_name = ext_original + ".enc"
    new_path = manager.protected_dir / new_name
    original_path.rename(new_path)
    
    status = manager.verify_canary(ext_original, current_path=new_path)
    all_passed &= check(f"Extension-changed file verified as '{status}'", status == "extension-changed")
except Exception as exc:
    all_passed = False
    check(f"Extension change check FAILED: {exc}", False)


# ── 6. Verification (Deleted) ─────────────────────────────────────────────
separator("6. Verify Deleted")
try:
    del_original = manager.canary_filenames[4]
    original_path = manager.protected_dir / del_original
    
    # Delete it
    original_path.unlink()
    
    status = manager.verify_canary(del_original)
    all_passed &= check(f"Deleted file verified as '{status}'", status == "deleted")
except Exception as exc:
    all_passed = False
    check(f"Delete check FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 1 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
