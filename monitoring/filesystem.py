"""
Filesystem Monitoring — Phase 3
Uses watchdog to detect tampering with canary files and groups rapid events.
"""

import threading
import time
from pathlib import Path
from typing import Callable, List, Set, Dict

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from canary.manager import CanaryManager
from evidence.logger import EvidenceLogger


class CanaryEventHandler(FileSystemEventHandler):
    def __init__(self, manager: CanaryManager, logger: EvidenceLogger, on_incident_callback: Callable[[Dict], None]):
        """
        Args:
            manager: CanaryManager instance to check baselines and verify files.
            logger: EvidenceLogger instance.
            on_incident_callback: Function to call when an event grouping window closes.
        """
        super().__init__()
        self.manager = manager
        self.logger = logger
        self.callback = on_incident_callback
        self.window_seconds = self.logger.event_grouping_window
        
        self._lock = threading.Lock()
        self._affected_canaries: Set[str] = set()
        self._timer: threading.Timer = None

    def _is_relevant_path(self, path_str: str) -> bool:
        """Check if the event path involves a registered canary."""
        if not path_str:
            return False
            
        path = Path(path_str)
        # Check if the filename exactly matches a canary, or if the original canary was renamed to .locked
        # We also want to catch if they rename a canary to something else entirely.
        # But watchdog gives us the src_path (old name) and dest_path (new name).
        
        # Is it in the protected dir?
        if path.parent.resolve() != self.manager.protected_dir.resolve():
            return False
            
        # If it's an exact canary name
        if path.name in self.manager.canary_filenames:
            return True
            
        # If the original name was a canary (e.g., watchdog tells us a canary was renamed to something else)
        # We handle this by passing both src and dest to this function below.
        
        return False

    def _handle_event(self, event: FileSystemEvent):
        """Process an incoming filesystem event."""
        src_path = getattr(event, 'src_path', None)
        dest_path = getattr(event, 'dest_path', None)
        
        affected_name = None
        if src_path:
            affected_name = self.manager.is_path_monitored(Path(src_path))
        if not affected_name and dest_path:
            affected_name = self.manager.is_path_monitored(Path(dest_path))
            
        if not affected_name:
            return

        with self._lock:
            self._affected_canaries.add(affected_name)

            
            # Reset or start the timer
            if self._timer is not None:
                self._timer.cancel()
                
            self._timer = threading.Timer(self.window_seconds, self._flush_incident)
            self._timer.daemon = True
            self._timer.start()

    def _flush_incident(self):
        """Called when the grouping timer expires."""
        with self._lock:
            if not self._affected_canaries:
                return
            
            # Take a snapshot and clear for the next potential incident
            canaries_to_check = list(self._affected_canaries)
            self._affected_canaries.clear()
            self._timer = None

        # Verify exact states now that the dust has settled
        details = []
        for name in canaries_to_check:
            status = self.manager.verify_canary(name)
            # It's possible the event was harmless noise and the file is actually unchanged
            if status != "unchanged":
                details.append({
                    "canary_name": name,
                    "state": status
                })
        
        if not details:
            # All events were harmless (e.g. just reading the file can sometimes trigger modify in Windows)
            return

        # Prepare incident dictionary to pass to callback
        incident_data = {
            "affected_canaries": details,
            "files_affected_count": len(details),
            # We don't have candidates yet, correlator will add them later
        }
        
        self.logger._console.info(f"Filesystem monitor grouping window closed. {len(details)} files tampered.")
        self.callback(incident_data)

    def on_created(self, event):
        self._handle_event(event)

    def on_modified(self, event):
        self._handle_event(event)

    def on_deleted(self, event):
        self._handle_event(event)

    def on_moved(self, event):
        self._handle_event(event)


class FilesystemMonitor:
    def __init__(self, manager: CanaryManager, logger: EvidenceLogger, on_incident_callback: Callable):
        self.manager = manager
        self.logger = logger
        self.callback = on_incident_callback
        self.observer = None
        self._event_handler = None
        self._watch_handles = []

    def start(self):
        """Start the watchdog observer loop in a background thread."""
        if self.observer is not None:
            return
            
        self._event_handler = CanaryEventHandler(self.manager, self.logger, self.callback)
        self.observer = Observer()
        self.observer.daemon = True
        self.refresh_watches()
        self.observer.start()
        self.logger.log_system_event("Filesystem monitor started")

    def refresh_watches(self):
        """Schedule or re-schedule watches for protected_dir and all monitored folders."""
        if self.observer is None or self._event_handler is None:
            return

        try:
            self.observer.unschedule_all()
        except Exception:
            pass
        self._watch_handles.clear()

        # 1. Schedule protected_dir recursively
        p_dir = Path(self.manager.protected_dir)
        p_dir.mkdir(parents=True, exist_ok=True)
        try:
            w = self.observer.schedule(self._event_handler, str(p_dir), recursive=True)
            self._watch_handles.append(w)
        except Exception as e:
            self.logger._console.warning(f"[MONITOR] Failed to watch protected directory: {e}")

        # 2. Schedule each monitored folder recursively
        for folder_str in getattr(self.manager, "monitored_folders", []):
            f_path = Path(folder_str)
            if f_path.exists() and f_path.is_dir():
                try:
                    w = self.observer.schedule(self._event_handler, str(f_path), recursive=True)
                    self._watch_handles.append(w)
                except Exception as e:
                    self.logger._console.warning(f"[MONITOR] Failed to watch folder {f_path}: {e}")

    def stop(self):
        """Stop the watchdog observer."""
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
            self._watch_handles.clear()
            self.logger.log_system_event("Filesystem monitor stopped")

