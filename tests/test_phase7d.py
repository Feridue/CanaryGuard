"""
Phase 7d verification script.
Tests the Desktop Notification (plyer) functionality.
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
separator("0. Setup Responder")
try:
    logger = EvidenceLogger()
    # Use observe mode so it doesn't try to suspend anything
    logger.config["mode"] = "Observe"
    
    responder = Responder(logger)
    all_passed &= check("Responder initialized", True)
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Fire Notification ──────────────────────────────────────────────────
separator("1. Fire Desktop Notification")
try:
    print("  Triggering notification via Responder.handle_incident()...")
    
    mock_incident = {
        "affected_canaries": [{"canary_name": "passwords_backup.txt", "state": "deleted"}],
        "files_affected_count": 1
    }
    
    mock_candidates = [
        {
            "pid": 9999,
            "name": "ransom.exe",
            "score": 95.0,
            "confidence": "High",
            "explanation": "Massive write burst"
        }
    ]
    
    # This should pop up a notification on the host machine
    result = responder.handle_incident(mock_incident, mock_candidates)
    
    all_passed &= check("Handle incident executed without crashing", True)
    
    print("\n" + "="*60)
    print("  ✅ ACTION REQUIRED: Check your desktop screen!")
    print("  You should see a Windows notification popping up.")
    print("="*60)
    
except Exception as exc:
    all_passed = False
    check(f"Notification FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  SCRIPT CHECKS PASSED.")
    print("  To meet the Definition of Done, please verbally confirm you saw the notification.")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
