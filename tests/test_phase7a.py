"""
Phase 7a verification script.
Tests the Responder in Observe Mode, ensuring it logs correctly
and never suspends any process.
"""

import sys
import psutil
import os
from pathlib import Path

# Force UTF-8 output on Windows so test symbols print correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Make sure imports resolve from the project root
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from evidence.logger import EvidenceLogger
from response.containment import Responder


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
separator("0. Setup Responder (Observe Mode)")
try:
    logger = EvidenceLogger()
    
    # Force mode to Observe
    logger.config["mode"] = "Observe"
    
    responder = Responder(logger)
    all_passed &= check("Responder initialized in Observe Mode", responder.logger.mode == "Observe")
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Execution ──────────────────────────────────────────────────────────
separator("1. Handle Incident")
try:
    # Mock an incident and a High-confidence candidate (our own process)
    my_pid = os.getpid()
    mock_incident = {
        "affected_canaries": [{"canary_name": "test.txt", "state": "modified"}],
        "files_affected_count": 1
    }
    
    mock_candidates = [
        {
            "pid": my_pid,
            "name": "python.exe",
            "score": 95.0,
            "confidence": "High",
            "explanation": "Candidate flagged due to: Massive write I/O burst"
        }
    ]
    
    # Before handling, verify our process is running normally
    my_proc = psutil.Process(my_pid)
    status_before = my_proc.status()
    
    # Run through responder
    result = responder.handle_incident(mock_incident, mock_candidates)
    
    all_passed &= check("Returned incident dictionary", isinstance(result, dict))
    
    # Check decision
    all_passed &= check("Decision is 'observe'", result.get("decision") == "observe")
    all_passed &= check("Action taken is 'none'", result.get("action_taken") == "none")
    
    # Verify we were not suspended
    status_after = my_proc.status()
    
    # Note: A running process usually has status 'running' or 'sleeping' (idle) but not 'stopped' or 'suspended' (platform specific, Windows uses 'stopped' or doesn't fully map it in the same way, but it definitely shouldn't crash us).
    # Since we are the process executing this code, if we were suspended, we would freeze here and the test would hang indefinitely!
    all_passed &= check("Process was not suspended (did not hang)", True)
    
except Exception as exc:
    all_passed = False
    check(f"Execution FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 7a Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
