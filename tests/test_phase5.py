"""
Phase 5 verification script.
Tests the ProcessCorrelator against a real run of the Test Simulator.
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
from canary.manager import CanaryManager
from monitoring.process import ProcessSampler
from simulator.ransom_sim import RansomwareSimulator
from analysis.correlator import ProcessCorrelator


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
    sampler = ProcessSampler(logger)
    correlator = ProcessCorrelator()
    
    # Clean slate
    manager.plant_canaries()
    all_passed &= check("Components initialized", True)
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Execution & Snapshots ──────────────────────────────────────────────
separator("1. Execution & Snapshots")
try:
    print("  Taking snapshot_before...")
    snapshot_before = sampler.get_snapshot()
    
    print("  Running simulator...")
    sim = RansomwareSimulator()
    
    # Suppress simulator stdout
    old_stdout = sys.stdout
    sys.stdout = open(os.devnull, "w")
    sim.run()
    sys.stdout = old_stdout
    
    print("  Taking snapshot_after...")
    snapshot_after = sampler.get_snapshot()
    
    # Mock incident based on Phase 3 output
    incident = {
        "affected_canaries": [{"canary_name": "test", "state": "modified"}],
        "files_affected_count": len(manager.canary_filenames)
    }
    
    all_passed &= check("Snapshots and incident captured", True)
except Exception as exc:
    all_passed = False
    check(f"Execution FAILED: {exc}", False)
    sys.exit(1)


# ── 2. Correlator Analysis ────────────────────────────────────────────────
separator("2. Correlator Analysis")
try:
    candidates = correlator.correlate(incident, snapshot_before, snapshot_after)
    
    all_passed &= check("Output is a list", isinstance(candidates, list))
    all_passed &= check("List is ranked (sorted by score desc)", 
                        all(candidates[i]["score"] >= candidates[i+1]["score"] 
                            for i in range(len(candidates)-1)))
                            
    # We expect our own Python test process to be flagged because IT ran the simulator
    my_pid = os.getpid()
    
    # Find our process in the candidates
    sim_candidate = next((c for c in candidates if c["pid"] == my_pid), None)
    
    all_passed &= check("Simulator process found in candidates", sim_candidate is not None)
    
    if sim_candidate:
        all_passed &= check(f"Simulator score is > 0 (Actual: {sim_candidate['score']})", sim_candidate["score"] > 0)
        all_passed &= check("Evidence collected", len(sim_candidate["evidence"]) > 0)
        print("  Simulator Candidate details:")
        print(f"    Name: {sim_candidate['name']}")
        print(f"    Score: {sim_candidate['score']}")
        print(f"    Evidence: {sim_candidate['evidence']}")
        
except Exception as exc:
    all_passed = False
    check(f"Analysis FAILED: {exc}", False)


# ── 3. Cleanup ─────────────────────────────────────────────────────────────
# Restore baseline to clean up sandbox
try:
    for filepath in manager.protected_dir.iterdir():
        if filepath.is_file():
            filepath.unlink()
    manager.plant_canaries()
except:
    pass


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 5 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
