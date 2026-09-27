"""
Phase 4 verification script.
Tests the ProcessSampler implementation, ensuring it captures metadata,
I/O counters, and strictly uses (PID, create_time) as the identity.
"""

import os
import sys
import psutil
from pathlib import Path

# Force UTF-8 output on Windows so test symbols print correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Make sure imports resolve from the project root
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from evidence.logger import EvidenceLogger
from monitoring.process import ProcessSampler


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
separator("0. Setup ProcessSampler")
try:
    logger = EvidenceLogger()
    sampler = ProcessSampler(logger)
    all_passed &= check("ProcessSampler initialized", True)
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Snapshot Collection ────────────────────────────────────────────────
separator("1. Snapshot Collection")
try:
    snapshot = sampler.get_snapshot()
    
    all_passed &= check("Snapshot returned a dictionary", isinstance(snapshot, dict))
    all_passed &= check("Snapshot contains processes (> 0)", len(snapshot) > 0)
    print(f"  Total processes captured: {len(snapshot)}")
except Exception as exc:
    all_passed = False
    check(f"Snapshot collection FAILED: {exc}", False)
    sys.exit(1)


# ── 2. Data Structure & Identity Verification ──────────────────────────────
separator("2. Data Structure & Identity Tracking")
try:
    # We use our own Python process to verify standard fields exist
    my_pid = os.getpid()
    my_proc = psutil.Process(my_pid)
    my_identity = (my_pid, my_proc.create_time())
    
    all_passed &= check("Keys are strictly (PID, create_time) tuples", all(isinstance(k, tuple) and len(k) == 2 for k in snapshot.keys()))
    
    all_passed &= check("Current test process found in snapshot", my_identity in snapshot)
    
    if my_identity in snapshot:
        data = snapshot[my_identity]
        
        # Verify required metadata is present
        all_passed &= check("Field present: 'name'", "name" in data and bool(data["name"]))
        all_passed &= check("Field present: 'exe'", "exe" in data)
        all_passed &= check("Field present: 'cmdline'", "cmdline" in data)
        all_passed &= check("Field present: 'ppid'", "ppid" in data)
        all_passed &= check("Field present: 'username'", "username" in data)
        
        # Verify IO counters
        all_passed &= check("Field present: 'io_counters'", "io_counters" in data)
        if data["io_counters"]:
            io = data["io_counters"]
            all_passed &= check("IO counters contain read/write bytes", "read_bytes" in io and "write_bytes" in io)
            
except Exception as exc:
    all_passed = False
    check(f"Verification FAILED: {exc}", False)


# ── 3. Exception Handling (Graceful degradation) ───────────────────────────
separator("3. Graceful degradation checks")
try:
    # Ensure some restricted processes (which usually lack IO counters) were still captured
    # rather than crashing the sampler.
    processes_without_io = [k for k, v in snapshot.items() if v.get("io_counters") is None]
    if processes_without_io:
        all_passed &= check(f"Captured {len(processes_without_io)} restricted processes without crashing", True)
    else:
        # If running as Administrator, all might have IO counters, which is fine, but we note it.
        print("  [INFO] All processes had accessible IO counters (likely running as Admin)")
        all_passed &= check("No crash occurred during enumeration", True)
except Exception as exc:
    all_passed = False
    check(f"Graceful degradation check FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 4 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
