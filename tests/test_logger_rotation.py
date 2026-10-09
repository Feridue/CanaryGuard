import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence.logger import EvidenceLogger


class EvidenceLoggerRotationTests(unittest.TestCase):
    def test_rotates_json_lines_and_retains_configured_backups(self):
        config = {
            "mode": "Observe",
            "protected_dir": "protected",
            "canary_files": ["canary.txt"],
            "event_grouping_window": 1,
            "confidence_thresholds": {"low": 20, "medium": 50, "high": 80},
            "allowlist": [],
            "log_dir": "",
            "log_file": "canaryguard.log",
        }

        with tempfile.TemporaryDirectory() as directory:
            config["log_dir"] = directory
            with (
                patch("evidence.logger._LOG_MAX_BYTES", 1),
                patch("evidence.logger._LOG_BACKUP_COUNT", 2),
            ):
                logger = EvidenceLogger(config=config)

            try:
                for index in range(5):
                    logger.log_system_event(f"rotation-event-{index}")

                log_path = Path(directory) / "canaryguard.log"
                retained_paths = [
                    log_path,
                    Path(f"{log_path}.1"),
                    Path(f"{log_path}.2"),
                ]
                self.assertTrue(all(path.exists() for path in retained_paths))
                self.assertFalse(Path(f"{log_path}.3").exists())

                records = []
                for path in retained_paths:
                    lines = path.read_text(encoding="utf-8").splitlines()
                    self.assertEqual(len(lines), 1)
                    records.append(json.loads(lines[0]))

                retained_messages = {record.get("message") for record in records}
                self.assertEqual(
                    retained_messages,
                    {
                        "rotation-event-2",
                        "rotation-event-3",
                        "rotation-event-4",
                    },
                )
            finally:
                logger._file_handler.close()


if __name__ == "__main__":
    unittest.main()
