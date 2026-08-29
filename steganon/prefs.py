"""Interface preferences.

Kept apart from the system settings, deliberately.

Language, window size and the like are about how the user sees the
application — not what it does to the network. Stored alongside the rules in
/etc, every language change would ask for an administrator password and
freeze the window while it waited. Here they are written to the user's own
folder, immediately and without questions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def _base() -> Path:
    override = os.environ.get("STEGANON_PREFS_DIR")
    if override:
        return Path(override)
    root = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(root) / "steganon"


FILE = _base() / "interface.json"

DEFAULTS: dict[str, object] = {
    "language": "",        # empty = follow the system
    "window_width": 480,
    "window_height": 0,     # 0 = measure it from the content
}


def load() -> dict:
    data = dict(DEFAULTS)
    try:
        data.update(json.loads(FILE.read_text(encoding="utf-8")))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return data


def save(**changes) -> None:
    data = load()
    data.update(changes)
    try:
        FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(FILE)
    except OSError:
        # Failing to save a preference is no reason to stop the application;
        # the change simply does not survive until the next start.
        pass


def get(key: str):
    return load().get(key, DEFAULTS.get(key))


# ── starting the window automatically ─────────────────────────────────────
#
# Separate from the service, because it is a different thing: the service sets
# up the protection and belongs to the system; the window is the front end and
# belongs to the user's session. The switch in the interface sets both, but
# they are written in different places — and only the first asks for rights.

AUTOSTART = _base().parent / "autostart" / "steganon.desktop"

ENTRY = """[Desktop Entry]
Type=Application
Name=Steganon
Name[el]=Στεγανό
Comment=All traffic through the tunnel, or none at all
Comment[el]=Όλη η κίνηση από το tunnel, ή καθόλου
Exec=steganon-gui --hidden
Icon=steganon
Terminal=false
X-GNOME-Autostart-enabled=true
"""


def autostart_enabled() -> bool:
    return AUTOSTART.exists()


def set_autostart(enabled: bool) -> bool:
    """Starts the window with the session, hidden in the tray."""
    try:
        if enabled:
            AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
            AUTOSTART.write_text(ENTRY, encoding="utf-8")
        else:
            AUTOSTART.unlink(missing_ok=True)
        return True
    except OSError:
        return False
