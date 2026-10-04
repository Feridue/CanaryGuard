"""
CanaryGuard — Phase 9a: System Tray Icon
Provides a background system tray icon using pystray and Pillow.
Runs detached alongside the Tkinter dashboard.
"""

import sys
import threading
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item, Menu


def create_shield_icon(size: int = 64) -> Image.Image:
    """
    Programmatically creates a shield icon for CanaryGuard
    so no external .ico or .png file is required.
    """
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Shield polygon coordinates
    points = [
        (size // 2, 4),                     # top center
        (size - 8, 12),                     # top right
        (size - 10, size // 2),             # right curve
        (size // 2, size - 4),              # bottom point
        (10, size // 2),                    # left curve
        (8, 12),                            # top left
    ]

    # Draw outer shield (deep emerald / dark cyan)
    draw.polygon(points, fill=(16, 120, 110, 255), outline=(32, 200, 180, 255))

    # Draw inner shield accent
    inner_points = [
        (size // 2, 10),
        (size - 14, 18),
        (size - 16, size // 2 - 2),
        (size // 2, size - 12),
        (16, size // 2 - 2),
        (14, 18),
    ]
    draw.polygon(inner_points, fill=(24, 160, 140, 255))

    # Draw white checkmark in center
    check_coords = [
        (size // 2 - 8, size // 2),
        (size // 2 - 2, size // 2 + 6),
        (size // 2 + 10, size // 2 - 6),
    ]
    draw.line(check_coords, fill=(255, 255, 255, 255), width=4)

    return image


class CanaryGuardTray:
    def __init__(self, engine, dashboard, on_quit_callback=None):
        self.engine = engine
        self.dashboard = dashboard
        self.on_quit_callback = on_quit_callback

        self.icon_image = create_shield_icon()
        self.tray_icon = None

    def _get_menu(self):
        def _get_pause_label(item):
            return "Resume Monitoring" if self.engine.is_paused else "Pause Monitoring"

        def _on_open_dashboard(icon, item):
            self.dashboard.show()

        def _on_toggle_pause(icon, item):
            if self.engine.is_paused:
                self.engine.resume()
                self.dashboard.status_var.set("🟢 MONITORING")
                self.dashboard.pause_btn.configure(text="Pause")
            else:
                self.engine.pause()
                self.dashboard.status_var.set("🟡 PAUSED")
                self.dashboard.pause_btn.configure(text="Resume")

        def _on_quit(icon, item):
            if self.on_quit_callback:
                self.on_quit_callback()
            else:
                self.stop()
                self.engine.stop()
                self.dashboard.root.destroy()
                sys.exit(0)

        return Menu(
            item("Open Dashboard", _on_open_dashboard, default=True),
            item(_get_pause_label, _on_toggle_pause),
            Menu.SEPARATOR,
            item("Quit CanaryGuard", _on_quit)
        )

    def start(self):
        """Starts the tray icon in a detached background thread."""
        self.tray_icon = pystray.Icon(
            name="CanaryGuard",
            icon=self.icon_image,
            title="CanaryGuard — Protection Active",
            menu=self._get_menu()
        )
        self.tray_icon.run_detached()

    def stop(self):
        """Stops the tray icon."""
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
