from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import os


class FileMonitorHandler(FileSystemEventHandler):
    """Handle file-system events."""

    def __init__(self, event_callback=None, allowed_extensions=None):
        super().__init__()
        self.event_callback = event_callback
        self.allowed_extensions = [
            ext.lower() for ext in (allowed_extensions or [])
        ]

    def _is_valid_file(self, file_path):
        """Check whether the file type should be monitored."""

        if not self.allowed_extensions:
            return True

        extension = os.path.splitext(file_path)[1].lower()
        return extension in self.allowed_extensions

    def _handle_event(self, event_type, file_path, dest_path=None):
        """Create and process a structured file event."""

        if not self._is_valid_file(file_path):
            return

        event_data = {
            "event_type": event_type,
            "file_path": file_path,
            "timestamp": datetime.now().isoformat()
        }

        if dest_path:
            event_data["dest_path"] = dest_path

        print(f"[{event_type}] {file_path}")

        if dest_path:
            print(f"    -> {dest_path}")

        print(f"    Time: {event_data['timestamp']}")

        if self.event_callback:
            self.event_callback(event_data)

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_event("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle_event(
                "MOVED",
                event.src_path,
                event.dest_path
            )


class FileMonitor:
    """Monitor a directory for file-system activity."""

    def __init__(
        self,
        target_directory,
        event_callback=None,
        allowed_extensions=None
    ):
        self.target_directory = target_directory
        self.event_callback = event_callback
        self.allowed_extensions = allowed_extensions or []
        self.observer = Observer()

    def start(self):
        """Start monitoring the target directory."""

        if not os.path.exists(self.target_directory):
            os.makedirs(self.target_directory)

        handler = FileMonitorHandler(
            event_callback=self.event_callback,
            allowed_extensions=self.allowed_extensions
        )

        self.observer.schedule(
            handler,
            self.target_directory,
            recursive=True
        )

        self.observer.start()

        print(f"[*] Monitoring: {self.target_directory}")

    def stop(self):
        """Stop monitoring."""

        self.observer.stop()
        self.observer.join()

        print("[*] Monitoring stopped.")