"""
CanaryGuard — Phase 8: Core Engine
Wires together all modules into a single background-thread engine.
The GUI (Phase 9) will call into this engine's public API.
"""

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
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

    Lifecycle
    ---------
    engine = CanaryGuardEngine()
    engine.start()          # starts monitoring
    engine.pause()          # pauses (monitor keeps running, no responses)
    engine.resume()         # resumes
    engine.stop()           # shuts everything down cleanly

    Runtime canary management
    -------------------------
    engine.add_canary(path)     # add a file to monitoring at runtime
    engine.remove_canary(path)  # remove a file from monitoring at runtime

    GUI integration
    ---------------
    engine.on_incident_callback = my_gui_function
    # my_gui_function(incident_dict) will be called on every incident
    engine.recent_incidents   # deque of last 50 incidents
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

        # Last 50 incidents for the dashboard
        self.recent_incidents: deque = deque(maxlen=50)

        # Optional GUI callback — set this before calling start()
        self.on_incident_callback: Optional[Callable[[dict], None]] = None

        # Background thread for the pre-incident process snapshot loop
        self._sampler_thread: Optional[threading.Thread] = None

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
        Add an existing file (or a new path) to the canary watch list at runtime.
        Saves the updated list to config.json.
        Returns True on success, False if the path is already monitored.
        """
        path = Path(filepath)
        name = path.name

        if name in self.manager.canary_filenames:
            return False

        # Copy the file into the protected directory if it lives elsewhere
        dest = self.manager.protected_dir / name
        if path.resolve() != dest.resolve():
            import shutil
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(path), str(dest))

        # Register the new canary
        self.manager.canary_filenames.append(name)
        self.manager._record_baseline()

        # Persist to config.json
        self._save_canary_list()
        self.logger.log_system_event(f"Canary added at runtime: {name}")
        return True

    def remove_canary(self, filename: str) -> bool:
        """
        Remove a canary file from the watch list at runtime.
        Does not delete the actual file. Saves the updated list to config.json.
        Returns True on success, False if the name wasn't in the list.
        """
        if filename not in self.manager.canary_filenames:
            return False

        self.manager.canary_filenames.remove(filename)
        self.manager.baselines.pop(filename, None)

        self._save_canary_list()
        self.logger.log_system_event(f"Canary removed at runtime: {filename}")
        return True

    def set_mode(self, mode: str) -> None:
        """Switch operating mode at runtime and persist to config.json."""
        valid = {"Observe", "Approval", "Automatic"}
        if mode not in valid:
            raise ValueError(f"Mode must be one of {valid}")
        self.logger.config["mode"] = mode
        self._save_config()
        self.logger.log_system_event(f"Mode changed to: {mode}")

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
        """Persist the current canary filename list back to config.json."""
        self.logger.config["canary_files"] = list(self.manager.canary_filenames)
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

