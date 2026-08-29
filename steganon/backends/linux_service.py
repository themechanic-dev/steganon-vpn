"""The service on Linux.

Two units, because they do different work at different moments: the firewall
loads before the network and depends on nothing; the connection needs a
network and comes after.
"""

from __future__ import annotations

import subprocess

UNITS = ("steganon-firewall.service", "steganon.service")


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True)


def install() -> bool:
    """The units are installed by install.sh; only the reload is left here."""
    return _systemctl("daemon-reload").returncode == 0


def uninstall() -> bool:
    for unit in UNITS:
        _systemctl("disable", "--now", unit)
    return True


def set_autostart(enabled: bool) -> bool:
    action = "enable" if enabled else "disable"
    return all(_systemctl(action, unit).returncode == 0 for unit in UNITS)


def autostart_enabled() -> bool:
    return _systemctl("is-enabled", UNITS[1]).stdout.strip() == "enabled"


def start() -> bool:
    return _systemctl("start", UNITS[1]).returncode == 0


def stop() -> bool:
    return _systemctl("stop", UNITS[1]).returncode == 0


def is_running() -> bool:
    return _systemctl("is-active", UNITS[1]).stdout.strip() == "active"


def installed() -> bool:
    return _systemctl("cat", UNITS[1]).returncode == 0
