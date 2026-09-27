"""
Phase 0 verification script.
Run this from the project root to confirm config loading and evidence logging work correctly.
"""

import json
import os
import sys
from pathlib import Path

# Force UTF-8 output on Windows so test symbols print correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Make sure imports resolve from the project root (works both as script and -m module)
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from evidence.logger import load_config, EvidenceLogger


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


# ── 1. Config loads without errors ────────────────────────────────────────
separator("1. Config loading")
try:
    config = load_config()
    all_passed &= check("Config file loaded", True)
    all_passed &= check("'mode' field present",         "mode" in config)
    all_passed &= check("'protected_dir' field present","protected_dir" in config)
    all_passed &= check("'canary_files' field present", "canary_files" in config)
    all_passed &= check("'event_grouping_window' present","event_grouping_window" in config)
    all_passed &= check("'allowlist' field present",    "allowlist" in config)
    all_passed &= check("'log_dir' field present",      "log_dir" in config)
    all_passed &= check("'log_file' field present",     "log_file" in config)
    all_passed &= check("mode is valid string",         config["mode"] in {"Observe","Approval","Automatic"})
    all_passed &= check("allowlist is a list",          isinstance(config["allowlist"], list))
    all_passed &= check("canary_files is a non-empty list",
                        isinstance(config["canary_files"], list) and len(config["canary_files"]) > 0)
    print(f"\n  Mode:              {config['mode']}")
    print(f"  Protected dir:     {config['protected_dir']}")
    print(f"  Canary files:      {len(config['canary_files'])} defined")
    print(f"  Grouping window:   {config['event_grouping_window']}s")
    print(f"  Allowlist entries: {len(config['allowlist'])}")
except Exception as exc:
    all_passed = False
    check(f"Config load FAILED: {exc}", False)


# ── 2. EvidenceLogger instantiation ───────────────────────────────────────
separator("2. EvidenceLogger instantiation")
try:
    logger = EvidenceLogger()
    all_passed &= check("EvidenceLogger created", True)
    all_passed &= check("Property: mode",         logger.mode in {"Observe","Approval","Automatic"})
    all_passed &= check("Property: protected_dir",bool(logger.protected_dir))
    all_passed &= check("Property: canary_files", len(logger.canary_files) > 0)
    all_passed &= check("Property: allowlist",    len(logger.allowlist) > 0)
    all_passed &= check("Log directory created",  Path(logger._log_dir).exists())
except Exception as exc:
    all_passed = False
    check(f"Logger init FAILED: {exc}", False)
    sys.exit(1)


# ── 3. Fake incident logging ───────────────────────────────────────────────
separator("3. Incident logging (fake incident)")
fake_incident = {
    "canary_affected": "passwords_backup.txt",
    "event_type": "modified",
    "candidates": [
        {
            "pid": 9999,
            "creation_time": "2026-09-15T20:00:00+00:00",
            "name": "test_process.exe",
            "score": 85.0,
            "confidence": "High",
            "evidence": ["open file handle", "elevated write I/O"]
        }
    ],
    "decision": "observe",
    "action_taken": "none",
    "files_affected_count": 1
}

try:
    incident_id = logger.log_incident(fake_incident)
    all_passed &= check("log_incident returned an incident_id", bool(incident_id))
    print(f"  Incident ID: {incident_id}")
except Exception as exc:
    all_passed = False
    check(f"log_incident FAILED: {exc}", False)


# ── 4. System event logging ────────────────────────────────────────────────
separator("4. System event logging")
try:
    logger.log_system_event("Phase 0 verification test run", extra={"test": True})
    all_passed &= check("log_system_event completed", True)
except Exception as exc:
    all_passed = False
    check(f"log_system_event FAILED: {exc}", False)


# ── 5. Verify log file contents ────────────────────────────────────────────
separator("5. Log file content verification")
log_path = Path(logger._log_file)
try:
    all_passed &= check("Log file exists", log_path.exists())
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    all_passed &= check("Log file has at least 3 lines", len(lines) >= 3)

    # Parse every line as JSON
    records = []
    parse_ok = True
    for i, line in enumerate(lines):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            parse_ok = False
            all_passed = False
            check(f"Line {i+1} is not valid JSON: {e}", False)
    all_passed &= check("Every log line is valid JSON", parse_ok)

    # Find the fake incident record
    incident_records = [r for r in records if r.get("record_type") == "incident"]
    all_passed &= check("At least one incident record written", len(incident_records) > 0)
    if incident_records:
        rec = incident_records[-1]
        all_passed &= check("Record has 'incident_id'",  "incident_id" in rec)
        all_passed &= check("Record has 'timestamp'",    "timestamp" in rec)
        all_passed &= check("Record has 'event_type'",   rec.get("event_type") == "modified")
        all_passed &= check("Record has 'candidates'",   "candidates" in rec)
        all_passed &= check("Record has 'decision'",     rec.get("decision") == "observe")
        print(f"\n  Sample record:")
        print("  " + json.dumps(rec, indent=2).replace("\n", "\n  "))

except Exception as exc:
    all_passed = False
    check(f"Log verification FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 0 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
