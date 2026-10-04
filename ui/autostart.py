"""
Windows Auto-Start on Boot utility for CanaryGuard.
Manages HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key.
"""

import sys
import winreg
from pathlib import Path

REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "CanaryGuard"


def get_command_string() -> str:
    """Returns the pythonw command string to run main.py silently without terminal."""
    python_exe = Path(sys.executable)
    # Prefer pythonw.exe if it exists alongside python.exe
    pythonw_exe = python_exe.with_name("pythonw.exe")
    exe_to_use = pythonw_exe if pythonw_exe.exists() else python_exe

    project_root = Path(__file__).resolve().parent.parent
    main_script = project_root / "main.py"

    return f'"{exe_to_use}" "{main_script}" --minimized'


def is_autostart_enabled() -> bool:
    """Check if CanaryGuard is configured in the Windows Run registry key."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY, 0, winreg.KEY_READ) as key:
            try:
                winreg.QueryValueEx(key, APP_NAME)
                return True
            except FileNotFoundError:
                return False
    except Exception:
        return False


def set_autostart(enable: bool) -> bool:
    """
    Enable or disable auto-start on boot via Windows Registry.
    Returns True on success, False on failure.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                cmd = get_command_string()
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
            return True
    except Exception as exc:
        print(f"[AUTOSTART] Error modifying registry: {exc}")
        return False
