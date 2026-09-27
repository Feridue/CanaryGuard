"""
Phase 6 verification script.
Tests the ConfidenceEngine mapping and explanation generation.
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
from analysis.confidence import ConfidenceEngine


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
    engine = ConfidenceEngine(logger)
    all_passed &= check("Components initialized", True)
except Exception as exc:
    all_passed = False
    check(f"Setup FAILED: {exc}", False)
    sys.exit(1)


# ── 1. Engine Evaluation ──────────────────────────────────────────────────
separator("1. Engine Evaluation")
try:
    # 3 mock candidates matching the 3 score tiers in our config
    # Config defaults: low=20, medium=50, high=80
    mock_candidates = [
        {"pid": 100, "score": 15.0, "evidence": ["Small write I/O burst: 0.5 MB"]},
        {"pid": 200, "score": 60.0, "evidence": ["High write I/O burst: 5.0 MB", "Process spawned during incident"]},
        {"pid": 300, "score": 90.0, "evidence": ["Massive write I/O burst: 50.0 MB", "Deleted multiple files"]}
    ]
    
    results = engine.evaluate(mock_candidates)
    
    all_passed &= check("Engine returned the correct number of candidates", len(results) == 3)
    
    # Verify mappings
    c_low = next(c for c in results if c["pid"] == 100)
    c_med = next(c for c in results if c["pid"] == 200)
    c_high = next(c for c in results if c["pid"] == 300)
    
    all_passed &= check("Score 15.0 mapped to 'Low' confidence", c_low["confidence"] == "Low")
    all_passed &= check("Score 60.0 mapped to 'Medium' confidence", c_med["confidence"] == "Medium")
    all_passed &= check("Score 90.0 mapped to 'High' confidence", c_high["confidence"] == "High")
    
    # Verify explanation strings
    all_passed &= check("Explanation string formed correctly (Single)", 
                        c_low["explanation"] == "Candidate flagged due to: Small write I/O burst: 0.5 MB")
                        
    all_passed &= check("Explanation string formed correctly (Multiple joined)", 
                        c_med["explanation"] == "Candidate flagged due to: High write I/O burst: 5.0 MB, Process spawned during incident")
                        
except Exception as exc:
    all_passed = False
    check(f"Evaluation FAILED: {exc}", False)


# ── Summary ────────────────────────────────────────────────────────────────
separator("RESULT")
if all_passed:
    print("  ALL CHECKS PASSED — Phase 6 Definition of Done met ✓")
else:
    print("  SOME CHECKS FAILED — review output above ✗")
    sys.exit(1)
