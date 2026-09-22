from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os


class FileMonitorHandler(FileSystemEventHandler):
    """Handle file-system events."""

    def on_created(self, event):
        if not event.is_directory:
            print(f"[CREATED] {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            print(f"[MODIFIED] {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[DELETED] {event.src_path}")

    def on_moved(self, event):
        if not event.is_directory:
            print(f"[MOVED] {event.src_path} -> {event.dest_path}")


class FileMonitor:
    """Monitor a directory for file-system activity."""

    def __init__(self, target_directory):
        self.target_directory = target_directory
        self.observer = Observer()

    def start(self):
        if not os.path.exists(self.target_directory):
            os.makedirs(self.target_directory)

        handler = FileMonitorHandler()

        self.observer.schedule(
            handler,
            self.target_directory,
            recursive=True
        )

        self.observer.start()

        print(f"[*] Monitoring: {self.target_directory}")