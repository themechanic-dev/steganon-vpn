"""The service on Windows.

One substantial difference from Linux changes the whole design: **firewall
rules on Windows are permanent**. They survive a reboot and are in force
before anything of ours loads.

On Linux a separate service had to run before the network, purely to rebuild
the firewall on every boot. Here that is unnecessary — and with it goes the
most dangerous moment of the Linux design, the gap between the network coming
up and the rules being enforced.

What is left is the connection and the supervision, running as a scheduled
task with system rights. That was chosen over a real service because a Windows
service needs a special wrapper to accept control commands — a dependency not
worth taking on for something that starts once.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TASK = "Steganon"
ROOT = Path(r"C:\Program Files\Steganon")


def _ps(script: str, check: bool = False) -> subprocess.CompletedProcess:
    from ..config import run
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        check=check,
    )


def _command() -> str:
    launcher = ROOT / "steganon.cmd"
    return str(launcher) if launcher.exists() else f'"{sys.executable}" -m steganon.cli'


def install() -> bool:
    """Creates the task, without enabling it."""
    script = f"""
$action  = New-ScheduledTaskAction -Execute '{_command()}' -Argument 'watch --connect'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# No time limit: supervision runs as long as the machine is on.
# No pausing on battery: protection does not depend on the mains.
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName '{TASK}' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Disable-ScheduledTask -TaskName '{TASK}' | Out-Null
'ok'
"""
    return _ps(script).stdout.strip().endswith("ok")


def uninstall() -> bool:
    return _ps(f"Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false "
               f"-ErrorAction SilentlyContinue; 'ok'").stdout.strip().endswith("ok")


def set_autostart(enabled: bool) -> bool:
    """The firewall stays either way; this only controls the connection."""
    verb = "Enable" if enabled else "Disable"
    result = _ps(f"{verb}-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue | Out-Null; 'ok'")
    return result.stdout.strip().endswith("ok")


def autostart_enabled() -> bool:
    out = _ps(f"(Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue).State").stdout.strip()
    return out not in ("", "Disabled")


def start() -> bool:
    return _ps(f"Start-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue; 'ok'"
               ).stdout.strip().endswith("ok")


def stop() -> bool:
    return _ps(f"Stop-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue; 'ok'"
               ).stdout.strip().endswith("ok")


def is_running() -> bool:
    out = _ps(f"(Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue).State").stdout.strip()
    return out == "Running"


def installed() -> bool:
    return bool(_ps(f"(Get-ScheduledTask -TaskName '{TASK}' "
                    f"-ErrorAction SilentlyContinue).TaskName").stdout.strip())


# ── starting the window automatically ─────────────────────────────────────

def gui_autostart_path() -> Path:
    return Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup" / "Steganon.cmd"


def set_gui_autostart(enabled: bool) -> bool:
    """Starts the window when the user logs in, hidden in the tray."""
    path = gui_autostart_path()
    try:
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f'@echo off\r\nstart "" "{ROOT / "steganon-gui.cmd"}" --hidden\r\n',
                encoding="ascii",
            )
        else:
            path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def gui_autostart_enabled() -> bool:
    return gui_autostart_path().exists()
