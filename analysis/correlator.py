"""
Correlator — Phase 5
Cross-references file incidents with process I/O counters to find candidates.
"""

from typing import Dict, List, Any, Tuple


class ProcessCorrelator:
    def __init__(self):
        pass

    def correlate(self, 
                  incident: Dict[str, Any], 
                  snapshot_before: Dict[Tuple[int, float], Dict[str, Any]], 
                  snapshot_after: Dict[Tuple[int, float], Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes process snapshots to identify potential candidates responsible
        for the given incident.
        
        Returns:
            A list of candidate dictionaries sorted by raw score (descending).
            Always returns a list, even if empty or single-element.
        """
        candidates = []
        
        # We only care about processes that exist in the 'after' snapshot 
        # (if a process exited instantly, we might miss its IO, which is a known limit of polling).
        for identity, proc_after in snapshot_after.items():
            score = 0.0
            evidence = []
            
            proc_before = snapshot_before.get(identity)
            
            # Check 1: Was the process newly created during the incident window?
            if not proc_before:
                score += 20.0
                evidence.append("Process spawned during incident window")
            
            # Check 2: I/O Write Delta
            io_after = proc_after.get('io_counters')
            io_before = proc_before.get('io_counters') if proc_before else None
            
            if io_after:
                write_bytes_after = io_after.get('write_bytes', 0)
                write_bytes_before = io_before.get('write_bytes', 0) if io_before else 0
                
                write_delta = write_bytes_after - write_bytes_before
                
                if write_delta > 0:
                    # Score scales loosely with write delta size.
                    # 1 MB = 1,000,000 bytes. 
                    # If write_delta is 10 MB, that's significant.
                    mb_written = write_delta / (1024 * 1024)
                    
                    if mb_written > 10:
                        score += 50.0
                        evidence.append(f"Massive write I/O burst: {mb_written:.1f} MB")
                    elif mb_written > 1:
                        score += 30.0
                        evidence.append(f"High write I/O burst: {mb_written:.1f} MB")
                    elif mb_written > 0.1:
                        score += 10.0
                        evidence.append(f"Elevated write I/O: {mb_written:.2f} MB")
                    elif mb_written > 0.005:
                        score += 5.0
                        evidence.append(f"Small write I/O burst: {mb_written:.3f} MB")
                    
                    # We only care about candidates that have at least some score
                    # (we don't want to list idle background processes)
                    
            if score > 0:
                candidates.append({
                    "pid": proc_after["pid"],
                    "creation_time": proc_after["create_time"],
                    "name": proc_after.get("name", "Unknown"),
                    "exe": proc_after.get("exe"),
                    "cmdline": proc_after.get("cmdline"),
                    "score": score,
                    "evidence": evidence
                })
                
        # Sort candidates by score descending
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates
