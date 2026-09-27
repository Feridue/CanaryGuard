"""
Process Sampling — Phase 4
Uses psutil to snapshot running processes and their I/O telemetry.
Identity is strictly tracked as (pid, creation_time) to avoid PID reuse confusion.
"""

import psutil
from typing import Dict, Any, Tuple

from evidence.logger import EvidenceLogger


class ProcessSampler:
    def __init__(self, logger: EvidenceLogger):
        self.logger = logger
        
    def get_snapshot(self) -> Dict[Tuple[int, float], Dict[str, Any]]:
        """
        Takes a point-in-time snapshot of all running processes.
        
        Returns:
            A dictionary where the key is the tuple (pid, creation_time),
            and the value is a dictionary of process metadata including
            I/O counters.
        """
        snapshot = {}
        
        # Iterate over all active processes
        for proc in psutil.process_iter(['pid', 'create_time', 'name', 'exe', 'cmdline', 'ppid', 'username']):
            try:
                # Gather basic info via the as_dict() helper, which uses the pre-fetched fields
                info = proc.info
                
                # Fetch IO counters safely (can fail for system/restricted processes)
                try:
                    io = proc.io_counters()
                    io_dict = {
                        'read_bytes': io.read_bytes,
                        'write_bytes': io.write_bytes,
                        'read_count': io.read_count,
                        'write_count': io.write_count
                    }
                except (psutil.AccessDenied, AttributeError, NotImplementedError):
                    # Some processes (or OS restrictions) don't allow IO counter access
                    io_dict = None
                
                info['io_counters'] = io_dict
                
                # The identity key is (PID, Creation Time)
                identity = (info['pid'], info['create_time'])
                snapshot[identity] = info
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process terminated while we were iterating or is restricted, skip it
                pass
                
        return snapshot
