"""
Phase 7c verification script.
Tests the Responder in Automatic Mode, verifying safety checks
and automatic suspension of valid threats.
"""

import sys
import psutil
import subprocess
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
separator("0. Setup Responder (Automatic Mode)")
try:
    logger = EvidenceLogger()
    
    # Force mode to Automatic
    logger.config["mode"] = "Automatic"
    
    responder = Responder(logger)
    all_passed &= check("Responder initialized in Automatic Mode", responder.logger.mode == "Automatic")
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# Spawn a dummy process that we can safely suspend
print("  Spawning dummy background process for testing...")
dummy_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
dummy_pid = dummy_proc.pid

mock_incident = {
    "affected_canaries": [{"canary_name": "test.txt", "state": "modified"}],
    "files_affected_count": 1
}


# ── 1. Safety Check: Allowlist ─────────────────────────────────────────────
separator("1. Verify Allowlist Safety Check")
try:
    # High confidence, but it's an OS critical process
    mock_candidates_allowlisted = [
        {
            "pid": dummy_pid,
            "name": "svchost.exe",
            "score": 95.0,
            "confidence": "High",
            "explanation": "Mock evidence"
        }
    ]
    
    result = responder.handle_incident(mock_incident.copy(), mock_candidates_allowlisted)
    
    all_passed &= check("Decision is 'allowlisted'", result.get("decision") == "allowlisted")
    all_passed &= check("Action taken is 'none'", result.get("action_taken") == "none")
    
    # Verify the dummy process is still running normally
    ps_proc = psutil.Process(dummy_pid)
    all_passed &= check("Process was not suspended", ps_proc.status() in (psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING))
    
except Exception as exc:
    all_passed = False
    check(f"Allowlist test FAILED: {exc}", False)


# ── 2. Safety Check: Low Confidence ────────────────────────────────────────
separator("2. Verify Low Confidence Safety Check")
try:
    # Unknown process, but low confidence
    mock_candidates_low_conf = [
        {
            "pid": dummy_pid,
            "name": "unknown.exe",
            "score": 25.0,
            "confidence": "Low",
            "explanation": "Mock evidence"
        }
    ]
    
    result = responder.handle_incident(mock_incident.copy(), mock_candidates_low_conf)
    
    all_passed &= check("Decision is 'denied'", result.get("decision") == "denied")
    all_passed &= check("Action taken is 'none'", result.get("action_taken") == "none")
    
    ps_proc = psutil.Process(dummy_pid)
    all_passed &= check("Process was not suspended", ps_proc.status() in (psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING))
    
except Exception as exc:
    all_passed = False
    check(f"Low confidence test FAILED: {exc}", False)


# ── 3. Valid Threat: Automatic Suspension ─────────────────────────────────
separator("3. Verify Automatic Suspension of Valid Threat")
try:
    # Unknown process AND High confidence
    mock_candidates_threat = [
        {
            "pid": dummy_pid,
            "name": "unknown_ransomware.exe",
            "score": 95.0,
            "confidence": "High",
            "explanation": "Mock evidence"
        }
    ]
    
    result = responder.handle_incident(mock_incident.copy(), mock_candidates_threat)
    
    all_passed &= check("Decision is 'auto_suspended'", result.get("decision") == "auto_suspended")
    all_passed &= check("Action taken is 'suspended'", result.get("action_taken") == "suspended")
    
    ps_proc = psutil.Process(dummy_pid)
    all_passed &= check("Process IS suspended by OS", ps_proc.status() == psutil.STATUS_STOPPED)
    
except Exception as exc:
    all_passed = False
    check(f"Valid threat test FAILED: {exc}", False)


# ── 4. Verify Reversibility (Resume) ───────────────────────────────────────
separator("4. Verify Reversibility (Resume)")
try:
    success = responder.resume_process(dummy_pid)
    all_passed &= check("Resume function returned True", success)
    
    ps_proc = psutil.Process(dummy_pid)
    all_passed &= check("Process is running again", ps_proc.status() in (psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING))
except Exception as exc:
    all_passed = False
    check(f"Resume test FAILED: {exc}", False)


# ── Cleanup ────────────────────────────────────────────────────────────────
try:
    dummy_proc.terminate()
except:
    pass

# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 7c Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
