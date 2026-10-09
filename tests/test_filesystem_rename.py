import tempfile
import unittest
from pathlib import Path

from watchdog.events import FileDeletedEvent, FileModifiedEvent, FileMovedEvent

from canary.manager import CanaryManager
from evidence.logger import EvidenceLogger
from monitoring.filesystem import CanaryEventHandler


class CanaryRenameMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.protected_dir = root / "protected"
        self.protected_dir.mkdir()
        self.logger = EvidenceLogger(config={
            "mode": "Observe",
            "protected_dir": str(self.protected_dir),
            "canary_files": ["decoy.txt"],
            "event_grouping_window": 60,
            "confidence_thresholds": {"low": 20, "medium": 50, "high": 80},
            "allowlist": [],
            "log_dir": str(root / "logs"),
            "log_file": "canaryguard.log",
        })
        self.manager = CanaryManager(self.logger)
        (self.protected_dir / "decoy.txt").write_text(
            "baseline contents",
            encoding="utf-8",
        )
        self.manager._record_baseline()
        self.incidents = []
        self.handler = CanaryEventHandler(
            self.manager,
            self.logger,
            self.incidents.append,
        )

    def tearDown(self):
        if self.handler._timer is not None:
            self.handler._timer.cancel()
        self.temp_dir.cleanup()

    def _flush(self):
        if self.handler._timer is not None:
            self.handler._timer.cancel()
        self.handler._flush_incident()

    def test_rename_is_classified_and_subsequent_modification_is_tracked(self):
        original = self.protected_dir / "decoy.txt"
        renamed = self.protected_dir / "decoy-renamed.txt"
        original.rename(renamed)

        self.handler.on_moved(FileMovedEvent(str(original), str(renamed)))
        self._flush()

        self.assertEqual(
            self.incidents[-1]["affected_canaries"][0]["state"],
            "renamed",
        )

        renamed.write_text("changed after rename", encoding="utf-8")
        self.handler.on_modified(FileModifiedEvent(str(renamed)))
        self._flush()

        self.assertEqual(
            self.incidents[-1]["affected_canaries"][0]["state"],
            "renamed",
        )

    def test_extension_change_is_classified_correctly(self):
        original = self.protected_dir / "decoy.txt"
        renamed = self.protected_dir / "decoy.txt.locked"
        original.rename(renamed)

        self.handler.on_moved(FileMovedEvent(str(original), str(renamed)))
        self._flush()

        self.assertEqual(
            self.incidents[-1]["affected_canaries"][0]["state"],
            "extension-changed",
        )

    def test_deletion_is_still_classified_as_deleted(self):
        original = self.protected_dir / "decoy.txt"
        original.unlink()

        self.handler.on_deleted(FileDeletedEvent(str(original)))
        self._flush()

        self.assertEqual(
            self.incidents[-1]["affected_canaries"][0]["state"],
            "deleted",
        )


if __name__ == "__main__":
    unittest.main()
