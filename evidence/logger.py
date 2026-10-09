"""
Evidence Logger — Phase 0
Provides structured, timestamped JSON incident logging for CanaryGuard.
All other modules use this logger as their output sink.
"""

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from logging.handlers import RotatingFileHandler


_LOG_MAX_BYTES = 10 * 1024 * 1024
_LOG_BACKUP_COUNT = 5


class _RaisingRotatingFileHandler(RotatingFileHandler):
    """Rotating handler that keeps file-write failures visible to callers."""

    def handleError(self, record: logging.LogRecord) -> None:
        error = sys.exc_info()[1]
        if error is not None:
            raise error
        super().handleError(record)


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

def load_config(config_path: str = None) -> dict:
    """
    Load and return the CanaryGuard configuration from config.json.

    Searches for config.json relative to this file's location if no path
    is provided. Raises FileNotFoundError if the file cannot be found, and
    ValueError if the JSON is malformed.
    """
    if config_path is None:
        # Walk up from evidence/ to project root, then find config.json
        project_root = Path(__file__).resolve().parent.parent
        config_path = project_root / "config.json"

    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"CanaryGuard config file not found at: {config_path}"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"config.json is not valid JSON: {exc}"
            ) from exc

    _validate_config(config)
    return config


def _validate_config(config: dict) -> None:
    """Raise ValueError if any required top-level keys are missing."""
    required_keys = [
        "mode",
        "protected_dir",
        "canary_files",
        "event_grouping_window",
        "confidence_thresholds",
        "allowlist",
        "log_dir",
        "log_file",
    ]
    missing = [k for k in required_keys if k not in config]
    if missing:
        raise ValueError(
            f"config.json is missing required keys: {missing}"
        )

    valid_modes = {"Observe", "Approval", "Automatic"}
    if config["mode"] not in valid_modes:
        raise ValueError(
            f"config 'mode' must be one of {valid_modes}, "
            f"got: {config['mode']!r}"
        )


# ---------------------------------------------------------------------------
# Evidence Logger
# ---------------------------------------------------------------------------

class EvidenceLogger:
    """
    Structured evidence logger for CanaryGuard incidents.

    Writes one JSON object per line to a rotating log file.  Every incident
    record is assigned a unique incident_id and a UTC timestamp.

    Usage
    -----
    logger = EvidenceLogger()            # loads config automatically
    logger.log_incident(incident_dict)   # write a full incident record
    logger.log_system_event("started")   # write a lightweight system note
    """

    def __init__(self, config: dict = None, config_path: str = None):
        """
        Initialise the logger.

        Parameters
        ----------
        config :
            Pre-loaded configuration dict.  If None, config.json is loaded
            automatically.
        config_path :
            Optional explicit path to config.json; passed through to
            load_config() if config is not supplied.
        """
        if config is None:
            config = load_config(config_path)

        self.config = config
        self._log_dir = Path(config["log_dir"])
        self._log_file = self._log_dir / config["log_file"]

        # Ensure the log directory exists
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self._file_handler = _RaisingRotatingFileHandler(
            self._log_file,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        self._file_handler.setFormatter(logging.Formatter("%(message)s"))

        # Set up Python's stdlib logger for human-readable console output
        self._console = logging.getLogger("canaryguard")
        if not self._console.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            self._console.addHandler(handler)
            self._console.setLevel(logging.INFO)

        self.log_system_event("EvidenceLogger initialised", extra={"log_file": str(self._log_file)})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_incident(self, incident_data: dict[str, Any]) -> str:
        """
        Write a structured incident record to the evidence log.

        A unique ``incident_id`` and UTC ``timestamp`` are injected
        automatically if not already present in *incident_data*.

        Parameters
        ----------
        incident_data :
            A dictionary describing the incident (see SRS §6.1 for the
            canonical field list).

        Returns
        -------
        str
            The incident_id assigned to this record.
        """
        record = self._build_record("incident", incident_data)
        self._write(record)
        self._console.info(
            "Incident logged  id=%s  event=%s  decision=%s",
            record["incident_id"],
            record.get("event_type", "unknown"),
            record.get("decision", "unknown"),
        )
        return record["incident_id"]

    def log_system_event(self, message: str, extra: dict = None) -> None:
        """
        Write a lightweight system-level note to the evidence log.

        Parameters
        ----------
        message :
            Human-readable description of the system event.
        extra :
            Optional key/value pairs to include in the JSON record.
        """
        payload = {"message": message}
        if extra:
            payload.update(extra)

        record = self._build_record("system_event", payload)
        self._write(record)
        self._console.info("System event: %s", message)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_record(self, record_type: str, data: dict) -> dict:
        """Return a new dict with injected metadata merged with *data*."""
        base = {
            "record_type": record_type,
            "incident_id": data.get("incident_id") or str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # data fields can override base fields if they supply incident_id
        return {**base, **data}

    def _write(self, record: dict) -> None:
        """Append *record* as a single JSON line to the log file."""
        line = json.dumps(record, ensure_ascii=False, default=str)
        log_record = logging.LogRecord(
            name="canaryguard.evidence",
            level=logging.INFO,
            pathname=str(self._log_file),
            lineno=0,
            msg=line,
            args=(),
            exc_info=None,
        )
        self._file_handler.handle(log_record)

    # ------------------------------------------------------------------
    # Properties exposing config fields to other modules
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        """Active operating mode: 'Observe', 'Approval', or 'Automatic'."""
        return self.config["mode"]

    @property
    def protected_dir(self) -> str:
        """Path to the directory being guarded."""
        return self.config["protected_dir"]

    @property
    def canary_files(self) -> list[str]:
        """List of canary file names to be planted."""
        return self.config["canary_files"]

    @property
    def canary_file_types(self) -> list[str]:
        """List of allowed canary file extensions."""
        return self.config.get("canary_file_types", [".docx", ".xlsx", ".pdf", ".txt"])

    @property
    def event_grouping_window(self) -> int:
        """Seconds within which events are merged into one incident."""
        return self.config["event_grouping_window"]

    @property
    def confidence_thresholds(self) -> dict:
        """Dict with 'low', 'medium', 'high' score thresholds."""
        return self.config["confidence_thresholds"]

    @property
    def allowlist(self) -> list[str]:
        """Process names exempt from automatic containment."""
        return self.config["allowlist"]
