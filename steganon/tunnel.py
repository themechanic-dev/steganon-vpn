"""The tunnel.

One profile, one location at a time. Changing country means rewriting the
profile and restarting — not letting OpenVPN pick.

The first design listed every location as consecutive "remote" lines, which is
possible because the provider's certificates work on all its servers — checked
by connecting with the Greek credentials to a US server. Measurement rejected
it: each name resolves to dozens of addresses in the same country, and OpenVPN
cycles among them instead of moving on to the next country. With the Greek
server deliberately blocked, three consecutive attempts all landed on Greek
addresses.

Explicit control was chosen instead: the supervisor decides when the location
changes. It costs a full reconnect, but it does what it says.
"""

from __future__ import annotations

import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .config import RUNTIME_DIR, Settings, restrict, run

def _openvpn() -> str:
    """The OpenVPN executable.

    On Windows it is not on the search path after installation, so the default
    location is checked as well.
    """
    found = shutil.which("openvpn")
    if found:
        return found
    if sys.platform.startswith("win"):
        for base in (r"C:\Program Files\OpenVPN", r"C:\Program Files (x86)\OpenVPN"):
            candidate = Path(base) / "bin" / "openvpn.exe"
            if candidate.exists():
                return str(candidate)
    return "openvpn"


# Tunnel interface names differ: "tun0" on Linux, TAP adapter names on
# Windows. Both are checked so the rest of the code needs no branching.
TUNNEL_PREFIXES = ("tun", "wg", "tap", "ovpn")

PIDFILE = RUNTIME_DIR / "openvpn.pid"
LOGFILE = RUNTIME_DIR / "openvpn.log"
GENERATED = RUNTIME_DIR / "active.ovpn"

# The options the provider hands out, minus the server line.
# On Windows, OpenVPN has to be told explicitly that it manages addresses and
# routes itself; without this it leaves the setup to the TAP driver and the
# routing is not applied reliably.
WINDOWS_OPTIONS = """route-method exe
ip-win32 dynamic
"""
# "block-outside-dns" was left out deliberately. It installs filters of its
# own in the Windows filtering platform — "Added block filters for all
# interfaces" — which coexist with our rules without appearing in the
# firewall. Two independent mechanisms blocking the same traffic make it
# impossible to diagnose when something does not get through, and our own rule
# for the name-resolution port already does that job.

BASE_OPTIONS = """client
dev tun
proto {proto}
resolv-retry infinite
redirect-gateway def1
persist-key
persist-tun
nobind
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
auth SHA256
ping 5
ping-restart 20
connect-timeout 10
explicit-exit-notify 2
remote-cert-tls server
route-delay 5
verb 3
auth-nocache
"""


class TunnelError(RuntimeError):
    pass


def build_profile(settings: Settings) -> str:
    """One profile, built from the location the user put first."""
    locations = settings.enabled_locations()
    if not locations:
        raise TunnelError("There is no enabled location.")

    first = locations[0]
    lines = [BASE_OPTIONS.format(proto=first.proto)]
    if sys.platform.startswith("win"):
        lines.append(WINDOWS_OPTIONS)

    # ONLY the first location goes into the profile.
    #
    # It would be natural to write them all as consecutive "remote" lines and
    # let OpenVPN walk the list. In practice that does not work: each server
    # name resolves to dozens of addresses in the same country, and after a
    # drop OpenVPN "persists" the last one it used. The result is endless
    # rotation among addresses of the same country — measured: three
    # consecutive attempts, all three Greek, while the Greek server was
    # deliberately blocked.
    #
    # Changing country belongs to the supervisor, which rewrites this profile
    # with a different location on top. Slower, but predictable and under
    # control.
    lines.append(f"remote {first.remote} {first.port} {first.proto}")
    lines.append("resolv-retry 20")

    certs = first.folder
    lines.append(f"ca {_path(certs / 'ca.crt')}")
    lines.append(f"cert {_path(certs / 'client.crt')}")
    lines.append(f"key {_path(certs / 'client.key')}")

    # This location's own credentials, and only if they exist.
    #
    # The line is omitted rather than pointed at a missing file: OpenVPN
    # treats "auth-user-pass" with an unreadable path as a fatal error, while
    # a setup that authenticates with the certificate alone needs no line at
    # all. Providers differ on this, and the profile the user imported is what
    # says which kind it is.
    if first.credentials.exists():
        lines.append(f"auth-user-pass {_path(first.credentials)}")

    return "\n".join(lines) + "\n"


def _path(path: Path) -> str:
    """A path as OpenVPN's config file accepts it.

    Inside those files a backslash is an escape character, not a folder
    separator. Every Windows path is therefore rejected as invalid, with a
    message that does not even name the offending line — OpenVPN exits
    immediately, writing nothing to the log.

    A forward slash is accepted by Windows just as well, so it is the simplest
    fix: no doubling and no quoting needed.
    """
    return str(path).replace("\\", "/")


def write_profile(settings: Settings, path: Path = GENERATED) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_profile(settings), encoding="utf-8")
    # The profile points at the credentials file but does not contain it.
    # It is restricted anyway: it reveals which servers are in use.
    restrict(path)
    return path


# ── lifecycle ─────────────────────────────────────────────────────────────


def is_running() -> bool:
    """Is a tunnel running that THIS application started?

    The distinction matters. The machine may already have a VPN set up
    elsewhere — by the network administrator, by another tool. A "tun0" we did
    not create proves nothing about our rules being in force, and counting it
    as success gives a false sense of protection — exactly the mistake a
    security tool is not allowed to make.
    """
    pid = _pid()
    if pid is None:
        return False
    return _is_our_openvpn(pid)


def _is_our_openvpn(pid: int) -> bool:
    """Is this process our OpenVPN?

    "Ours" is checked from the command line, not from the id alone: a process
    id is recycled and could belong to an unrelated process started later.
    """
    if sys.platform.startswith("win"):
        out = run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"]
        ).stdout
        return "openvpn" in out.lower() and GENERATED.name in out

    if not Path(f"/proc/{pid}").exists():
        return False
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return False
    return "openvpn" in cmdline.lower() and str(GENERATED) in cmdline


def _pid() -> int | None:
    try:
        return int(PIDFILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def start(settings: Settings, wait: int = 60) -> tuple[bool, str]:
    """Brings the tunnel up and waits until it is genuinely ready."""
    if is_running():
        return True, "The tunnel is already running."

    profile = write_profile(settings)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    LOGFILE.write_text("", encoding="utf-8")

    # The tunnel has to outlive the command that started it — otherwise the
    # connection drops the moment that command reports "ready". The two
    # systems ask for this differently: on Linux a new session is enough, on
    # Windows it needs an explicit detach from the parent process and from its
    # console.
    if sys.platform.startswith("win"):
        detach = {
            "creationflags": (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        }
    else:
        detach = {"start_new_session": True}

    proc = subprocess.Popen(
        [_openvpn(), "--config", str(profile), "--log", str(LOGFILE),
         "--writepid", str(PIDFILE)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **detach,
    )

    deadline = time.time() + wait
    while time.time() < deadline:
        if proc.poll() is not None:
            return False, _last_error() or "OpenVPN exited immediately."
        log = _read_log()
        if "Initialization Sequence Completed" in log:
            # route-delay means the routes are installed a moment later.
            time.sleep(2)
            return True, f"Connected: {current_server() or 'unknown server'}"
        if "AUTH_FAILED" in log:
            stop()
            return False, "The provider rejected the credentials."
        time.sleep(1)

    stop()
    return False, "Timed out — the connection did not complete."


def stop() -> None:
    """Closes the tunnel cleanly.

    On Linux SIGTERM triggers "explicit-exit-notify", which tells the server.
    Windows has no equivalent signal for a process that shares no console, so
    the shutdown is abrupt — the session times out on the server instead of
    being closed with a notice.
    """
    pid = _pid()

    if sys.platform.startswith("win"):
        if pid:
            run(["taskkill", "/F", "/PID", str(pid)])
        # Fallback: if the pid file is missing or stale, we do not leave an
        # orphaned tunnel holding the routing.
        run(["taskkill", "/F", "/IM", "openvpn.exe"])
    else:
        if pid:
            try:
                import os
                os.kill(pid, signal.SIGTERM)
                for _ in range(20):
                    if not Path(f"/proc/{pid}").exists():
                        break
                    time.sleep(0.25)
            except (ProcessLookupError, PermissionError):
                pass
        run(["pkill", "-f", f"openvpn --config {GENERATED}"])

    PIDFILE.unlink(missing_ok=True)


def _read_log() -> str:
    try:
        return LOGFILE.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def _last_error() -> str:
    for line in reversed(_read_log().splitlines()):
        if any(k in line for k in ("ERROR", "AUTH_FAILED", "Cannot resolve", "TLS Error")):
            return line.strip()
    return ""


def current_server() -> str | None:
    """The server we are connected to, as its certificate declares it."""
    matches = re.findall(r"VERIFY OK: depth=0, CN=([^\s,]+)", _read_log())
    return matches[-1] if matches else None


def tunnel_interface() -> str | None:
    """The tunnel interface name, if there is one."""
    if sys.platform.startswith("win"):
        out = run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and "
             "($_.InterfaceDescription -like '*TAP*' -or "
             "$_.InterfaceDescription -like '*Wintun*')} "
             "| Select-Object -First 1 -ExpandProperty Name"]
        ).stdout.strip()
        return out or None

    out = run(["ip", "-brief", "link", "show"]).stdout
    for line in out.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith(TUNNEL_PREFIXES):
            return name
    return None


def routes_through_tunnel() -> bool:
    """Checks whether internet traffic really goes through the tunnel.

    "redirect-gateway def1" does not change the default route; it adds two /1
    routes that override it. The only reliable question is "where would an
    outbound packet actually leave from".
    """
    if sys.platform.startswith("win"):
        # The equivalent question: which interface would serve an address
        # outside the local network. It returns that interface's name, which
        # is compared against the tunnel's.
        out = run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Find-NetRoute -RemoteIPAddress 8.8.8.8 -ErrorAction SilentlyContinue "
             "| Select-Object -First 1).InterfaceAlias"]
        ).stdout.strip()
        iface = tunnel_interface()
        return bool(out and iface and out == iface)

    out = run(["ip", "route", "get", "8.8.8.8"]).stdout
    match = re.search(r"dev (\w+)", out)
    return bool(match and match.group(1).startswith(TUNNEL_PREFIXES))
