"""Picking an implementation per operating system.

The core — settings, health checks, location management — is shared. What
differs is two things with no equivalent between the systems: how traffic is
blocked, and how you set up a service that starts before the network.

Every implementation offers the same interface, so the rest of the code does
not need to know where it runs.
"""

from __future__ import annotations

import sys


def name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def firewall():
    """The firewall implementation for the current system."""
    if name() == "windows":
        from . import windows_firewall as backend
    else:
        from . import linux_firewall as backend
    return backend


def service():
    """The service implementation for the current system."""
    if name() == "windows":
        from . import windows_service as backend
    else:
        from . import linux_service as backend
    return backend


def supported() -> bool:
    return name() in ("linux", "windows")
