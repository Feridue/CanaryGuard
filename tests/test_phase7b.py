"""
Phase 7b verification script.
Tests the Responder in Approval Mode, verifying interactive prompts and suspension behavior.
"""

import sys
import psutil
import subprocess
import time
import builtins
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
separator("0. Setup Responder (Approval Mode)")
try:
    logger = EvidenceLogger()
    
    # Force mode to Approval
    logger.config["mode"] = "Approval"
    
    responder = Responder(logger)
    all_passed &= check("Responder initialized in Approval Mode", responder.logger.mode == "Approval")
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# Spawn a dummy process that we can safely suspend
print("  Spawning dummy background process for testing...")
# Just sleep for 10 seconds
dummy_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
dummy_pid = dummy_proc.pid

mock_incident = {
    "affected_canaries": [{"canary_name": "test.txt", "state": "modified"}],
    "files_affected_count": 1
}

mock_candidates = [
    {
        "pid": dummy_pid,
        "name": "dummy.exe",
        "score": 95.0,
        "confidence": "High",
        "explanation": "Candidate flagged due to: Mock evidence"
    }
]

# We need to mock the built-in input() function to simulate operator behavior
original_input = builtins.input

# ── 1. Simulate Operator Decline ('N') ─────────────────────────────────────
separator("1. Simulate Operator Decline ('n')")
try:
    # Mock input to return 'n'
    builtins.input = lambda prompt: 'n'
    
    result = responder.handle_incident(mock_incident.copy(), mock_candidates.copy())
    
    all_passed &= check("Decision is 'denied'", result.get("decision") == "denied")
    all_passed &= check("Action taken is 'none'", result.get("action_taken") == "none")
    
    # Verify the dummy process is still running normally
    ps_proc = psutil.Process(dummy_pid)
    all_passed &= check("Process was not suspended", ps_proc.status() in (psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING))
    
except Exception as exc:
    all_passed = False
    check(f"Decline test FAILED: {exc}", False)


# ── 2. Simulate Operator Approve ('Y') ─────────────────────────────────────
separator("2. Simulate Operator Approve ('y')")
try:
    # Mock input to return 'y'
    builtins.input = lambda prompt: 'y'
    
    result = responder.handle_incident(mock_incident.copy(), mock_candidates.copy())
    
    all_passed &= check("Decision is 'approved'", result.get("decision") == "approved")
    all_passed &= check("Action taken is 'suspended'", result.get("action_taken") == "suspended")
    
    # Verify the dummy process is actually suspended
    ps_proc = psutil.Process(dummy_pid)
    # On Windows, psutil returns STATUS_STOPPED for suspended processes
    all_passed &= check("Process is suspended by OS", ps_proc.status() == psutil.STATUS_STOPPED)
    
except Exception as exc:
    all_passed = False
    check(f"Approve test FAILED: {exc}", False)


# ── 3. Verify Reversibility (Resume) ───────────────────────────────────────
separator("3. Verify Reversibility (Resume)")
try:
    success = responder.resume_process(dummy_pid)
    all_passed &= check("Resume function returned True", success)
    
    ps_proc = psutil.Process(dummy_pid)
    all_passed &= check("Process is running again", ps_proc.status() in (psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING))
except Exception as exc:
    all_passed = False
    check(f"Resume test FAILED: {exc}", False)


# ── Cleanup ────────────────────────────────────────────────────────────────
builtins.input = original_input
try:
    dummy_proc.terminate()
except:
    pass

# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 7b Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
