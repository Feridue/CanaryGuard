import time
from monitoring.file_monitor import FileMonitor

monitor = FileMonitor("./data/test_sandbox")
monitor.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Monitoring stopped.")