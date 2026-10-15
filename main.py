"""
CanaryGuard — Phase 8: Core Engine
Wires together all modules into a single background-thread engine.
The GUI (Phase 9) will call into this engine's public API.
"""

import os
import sys
from pathlib import Path

# Force current working directory to project root so all relative paths resolve reliably
PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from canary.manager import CanaryManager
from monitoring.filesystem import FilesystemMonitor
from monitoring.process import ProcessSampler
from analysis.correlator import ProcessCorrelator
from analysis.confidence import ConfidenceEngine
from response.containment import Responder
from evidence.logger import EvidenceLogger


class CanaryGuardEngine:
    """
    The central engine that runs CanaryGuard as a background thread.
    """

    def __init__(self, config_path: str = None):
        self.logger = EvidenceLogger(config_path=config_path)
        self.manager = CanaryManager(self.logger)
        self.sampler = ProcessSampler(self.logger)
        self.correlator = ProcessCorrelator()
        self.confidence_engine = ConfidenceEngine(self.logger)
        self.responder = Responder(self.logger)

        self._monitor: Optional[FilesystemMonitor] = None
        self._paused = False
        self._running = False

        # Rolling snapshot taken just before each incident window closes
        self._snapshot_before: dict = {}

        # Last 50 incidents for the dashboard (loaded from disk on startup)
        self.recent_incidents: deque = deque(maxlen=50)
        self._load_persisted_incidents()

        # Optional GUI callback — set this before calling start()
        self.on_incident_callback: Optional[Callable[[dict], None]] = None

        # Background thread for the pre-incident process snapshot loop
        self._sampler_thread: Optional[threading.Thread] = None

    def _load_persisted_incidents(self) -> None:
        """Load recent historical incidents from canaryguard.log into memory."""
        log_file = getattr(self.logger, "_log_file", None)
        if not log_file or not Path(log_file).exists():
            return

        try:
            incidents = []
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("record_type") == "incident":
                            incidents.append(record)
                    except json.JSONDecodeError:
                        continue

            for inc in incidents[-50:]:
                self.recent_incidents.appendleft(inc)
        except Exception as e:
            if hasattr(self.logger, "_console"):
                self.logger._console.warning(f"[ENGINE] Could not load past incidents: {e}")


    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Plant canaries, start filesystem monitor, begin process sampling."""
        if self._running:
            return

        self._running = True
        self._paused = False

        # Plant decoy files and record baselines
        self.manager.plant_canaries()

        # Take initial snapshot
        self._snapshot_before = self.sampler.get_snapshot()

        # Start the rolling process sampler in a background thread
        self._sampler_thread = threading.Thread(
            target=self._sampler_loop, daemon=True, name="ProcessSamplerLoop"
        )
        self._sampler_thread.start()

        # Start the watchdog filesystem monitor
        self._monitor = FilesystemMonitor(
            manager=self.manager,
            logger=self.logger,
            on_incident_callback=self._on_incident
        )
        self._monitor.start()

        self.logger.log_system_event("CanaryGuard engine started", extra={
            "mode": self.logger.mode,
            "protected_dir": str(self.manager.protected_dir),
            "canary_count": len(self.manager.canary_filenames)
        })

    def stop(self) -> None:
        """Stop the filesystem monitor and sampler loop."""
        self._running = False
        if self._monitor:
            self._monitor.stop()
            self._monitor = None
        self.logger.log_system_event("CanaryGuard engine stopped")

    def pause(self) -> None:
        """
        Pause response actions. The filesystem monitor keeps watching but
        incidents will be logged only, regardless of mode.
        """
        self._paused = True
        self.logger.log_system_event("Engine paused — monitoring active, responses suppressed")

    def resume(self) -> None:
        """Resume normal response actions."""
        self._paused = False
        self.logger.log_system_event("Engine resumed — full response active")

    # ── Runtime canary management ───────────────────────────────────────────

    def add_canary(self, filepath: str) -> bool:
        """
        Add an existing file to be monitored at runtime directly in-place.
        Saves the updated list to config.json.
        Returns True on success, False if already monitored or invalid.
        """
        p = Path(filepath).resolve()
        if not p.exists() or not p.is_file():
            return False

        # If inside protected sandbox directory, add to standard canary_filenames
        try:
            if p.is_relative_to(self.manager.protected_dir.resolve()):
                if p.name in self.manager.canary_filenames:
                    return False
                self.manager.canary_filenames.append(p.name)
                self.manager._record_baseline()
                self._save_canary_list()
                if self._monitor:
                    self._monitor.refresh_watches()
                self.logger.log_system_event(f"Canary decoy added: {p.name}")
                return True
        except (ValueError, AttributeError):
            pass

        # Otherwise, monitor the file in-place where it actually lives
        success = self.manager.add_custom_canary(str(p))
        if success:
            self._save_canary_list()
            if self._monitor:
                self._monitor.refresh_watches()
        return success

    def remove_canary(self, filename_or_path: str) -> bool:
        """
        Remove a canary file from monitoring at runtime.
        Does not delete the actual file. Saves the updated list to config.json.
        """
        # 1. Try removing from custom_canaries
        if self.manager.remove_custom_canary(filename_or_path):
            self._save_canary_list()
            if self._monitor:
                self._monitor.refresh_watches()
            return True

        # 2. Try removing from standard canary_filenames
        target_name = Path(filename_or_path).name
        if target_name in self.manager.canary_filenames:
            self.manager.canary_filenames.remove(target_name)
            self.manager.baselines.pop(target_name, None)
            self._save_canary_list()
            if self._monitor:
                self._monitor.refresh_watches()
            self.logger.log_system_event(f"Canary removed: {target_name}")
            return True

        return False

    def set_mode(self, mode: str) -> None:
        """Switch operating mode at runtime and persist to config.json."""
        valid = {"Observe", "Approval", "Automatic"}
        if mode not in valid:
            raise ValueError(f"Mode must be one of {valid}")
        self.logger.config["mode"] = mode
        self._save_config()
        self.logger.log_system_event(f"Mode changed to: {mode}")

    def add_folder(self, folderpath: str) -> bool:
        """Add a directory to monitor recursively at runtime."""
        success = self.manager.add_folder(folderpath)
        if success:
            self._save_config()
            if self._monitor:
                self._monitor.refresh_watches()
        return success

    def remove_folder(self, folderpath: str) -> bool:
        """Remove a directory from monitoring at runtime."""
        success = self.manager.remove_folder(folderpath)
        if success:
            self._save_config()
            if self._monitor:
                self._monitor.refresh_watches()
        return success

    # ── Process Containment Management ─────────────────────────────────────

    @property
    def suspended_processes(self) -> dict:
        """Return dict of currently suspended processes {pid: info}."""
        return dict(getattr(self.responder, "suspended_processes", {}))

    def resume_process(self, pid: int) -> bool:
        """Resume a suspended process."""
        return self.responder.resume_process(pid)

    def kill_process(self, pid: int) -> bool:
        """Permanently terminate a suspended or hostile process."""
        return self.responder.kill_process(pid)

    # ── Properties for GUI ─────────────────────────────────────────────────

    @property
    def mode(self) -> str:
        return self.logger.mode

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def canary_files(self) -> list:
        return list(self.manager.canary_filenames)

    @property
    def custom_canaries(self) -> list:
        return list(getattr(self.manager, "custom_canaries", []))

    @property
    def monitored_folders(self) -> list:
        return list(getattr(self.manager, "monitored_folders", []))



    # ── Internal ───────────────────────────────────────────────────────────

    def _sampler_loop(self) -> None:
        """
        Continuously refresh the pre-incident snapshot every second.
        This gives the correlator a fresh baseline to diff against when
        an incident fires.
        """
        while self._running:
            try:
                self._snapshot_before = self.sampler.get_snapshot()
            except Exception as e:
                self.logger._console.warning(f"[SAMPLER] Snapshot error (non-fatal): {e}")
            time.sleep(1)

    def _on_incident(self, incident_data: dict) -> None:
        """
        Internal callback fired by the FilesystemMonitor when an incident
        is confirmed. Runs the full: correlate -> score -> respond -> log pipeline.
        """
        if not self._running:
            return

        import traceback

        try:
            # 1. Snapshot AFTER the incident
            snapshot_after = self.sampler.get_snapshot()

            # 2. Correlate: find candidate processes
            candidates = self.correlator.correlate(
                incident_data,
                self._snapshot_before,
                snapshot_after
            )

            # 3. Score: map raw scores to Low/Medium/High + explanations
            candidates = self.confidence_engine.evaluate(candidates)

            # 4. Temporarily override mode if paused
            original_mode = self.logger.config.get("mode")
            if self._paused:
                self.logger.config["mode"] = "Observe"

            # 5. Respond (also fires desktop notification internally)
            result = self.responder.handle_incident(incident_data, candidates)

            # Restore mode
            if self._paused:
                self.logger.config["mode"] = original_mode

            # 6. Log to evidence file
            incident_id = self.logger.log_incident(result)
            result["incident_id"] = incident_id
            result["logged_at"] = datetime.now(timezone.utc).isoformat()

            # 7. Add to in-memory recent incidents list
            self.recent_incidents.appendleft(result)


            # 8. Notify GUI if a callback is registered
            if self.on_incident_callback:
                try:
                    self.on_incident_callback(result)
                except Exception as e:
                    self.logger._console.warning(f"[ENGINE] GUI callback error: {e}")

        except Exception as e:
            self.logger._console.error(
                f"[ENGINE] Error processing incident: {e}\n{traceback.format_exc()}"
            )


    def _save_canary_list(self) -> None:
        """Persist the current canary lists and folders back to config.json."""
        self.logger.config["canary_files"] = list(self.manager.canary_filenames)
        self.logger.config["custom_canaries"] = list(getattr(self.manager, "custom_canaries", []))
        self.logger.config["monitored_folders"] = list(getattr(self.manager, "monitored_folders", []))
        self._save_config()


    def _save_config(self) -> None:
        """Write the current in-memory config back to config.json."""
        project_root = Path(__file__).resolve().parent
        config_path = project_root / "config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.logger.config, f, indent=2)


# ── Entry point ───────────────────────────────────────────────────────────

def run_cli(engine: CanaryGuardEngine):
    """Run CanaryGuard in headless terminal mode until Ctrl+C."""
    import signal

    engine.start()

    print("\n" + "=" * 60)
    print("  CanaryGuard Protection Active (CLI Mode)")
    print(f"  Mode       : {engine.mode}")
    print(f"  Watching   : {engine.manager.protected_dir}")
    print(f"  Canaries   : {len(engine.canary_files)} files")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    stop_event = threading.Event()

    def _handle_signal(sig, frame):
        print("\nStopping CanaryGuard...")
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    stop_event.wait()
    engine.stop()
    print("CanaryGuard stopped. Goodbye.")


def run_gui(engine: CanaryGuardEngine, start_minimized: bool = False):
    """Run CanaryGuard as a desktop application with System Tray and Dashboard GUI."""
    from ui.dashboard import CanaryGuardDashboard
    from ui.tray import CanaryGuardTray

    engine.start()

    tray = None
    dashboard = None

    def _quit_all():
        if tray:
            tray.stop()
        engine.stop()
        if dashboard and dashboard.root:
            try:
                dashboard.root.destroy()
            except Exception:
                pass
        sys.exit(0)

    dashboard = CanaryGuardDashboard(engine, on_quit_callback=_quit_all)
    tray = CanaryGuardTray(engine, dashboard, on_quit_callback=_quit_all)
    tray.start()

    if start_minimized:
        dashboard.hide()
    else:
        dashboard.show()

    try:
        dashboard.root.mainloop()
    except (KeyboardInterrupt, SystemExit):
        _quit_all()


def main():
    import sys

    engine = CanaryGuardEngine()

    # CLI flag check
    if "--cli" in sys.argv or "--terminal" in sys.argv:
        run_cli(engine)
    else:
        start_minimized = "--minimized" in sys.argv or "--tray" in sys.argv
        run_gui(engine, start_minimized=start_minimized)


if __name__ == "__main__":
    main()

