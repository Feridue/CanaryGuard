import json
import time

from monitoring.file_monitor import FileMonitor


def load_config():
    """Load CanaryGuard configuration."""
    with open("config.json", "r", encoding="utf-8") as file:
        return json.load(file)


def main():
    config = load_config()

    target_directory = config["target_directory"]
    monitored_file_types = config.get("monitored_file_types", [])

    monitor = FileMonitor(
        target_directory,
        allowed_extensions=monitored_file_types
    )

    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()


if __name__ == "__main__":
    main()