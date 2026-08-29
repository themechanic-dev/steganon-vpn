"""The firewall on Windows.

The principle is the same as on Linux — whatever is not explicitly allowed
does not leave — but the mechanism differs substantially.

On Linux one rule set replaces the previous one atomically. Windows has a
permanent firewall with profiles and coexisting rules, so we have to intervene
without trampling on what the user already has. Our rules share a common name
prefix, so they can be recognised and removed without touching anything else.

The default outbound action is set to "block" on all three profiles. That is
the equivalent of "policy drop": every failure ends in "no network" and never
in "no protection".
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from pathlib import Path

PREFIX = "Steganon"
PROFILES = ("Domain", "Private", "Public")

STATE_DIR = Path(r"C:\ProgramData\Steganon")
STATUS_FILE = STATE_DIR / "firewall.json"
BACKUP_FILE = STATE_DIR / "previous-policy.json"
CACHED_IPS = STATE_DIR / "server-ips.json"


class FirewallError(RuntimeError):
    pass


def _ps(script: str, check: bool = True) -> subprocess.CompletedProcess:
    """Runs PowerShell. "-NonInteractive" prevents silent hangs."""
    from ..config import run
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        check=check,
    )


def available() -> bool:
    try:
        return _ps("Get-Command Set-NetFirewallProfile | Out-Null; 'ok'",
                   check=False).returncode == 0
    except FileNotFoundError:
        return False


# ── rules ─────────────────────────────────────────────────────────────────


def tunnel_adapters() -> list[str]:
    """The names of the adapters belonging to a tunnel.

    Interface type is not enough. The TAP adapter OpenVPN creates reports
    itself as virtual Ethernet, not as "remote access" — a rule that filters
    by type never matches it, and traffic through the tunnel is silently
    blocked while everything looks right.
    """
    out = _ps(
        "Get-NetAdapter | Where-Object { "
        "$_.InterfaceDescription -like '*TAP*' -or "
        "$_.InterfaceDescription -like '*Wintun*' -or "
        "$_.InterfaceDescription -like '*OpenVPN*' -or "
        "$_.InterfaceDescription -like '*WireGuard*' } "
        "| Select-Object -ExpandProperty Name",
        check=False,
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def _rules(settings, server_ips: list[str]) -> list[str]:
    """The commands that build the firewall, in the order they must run."""
    v4 = [ip for ip in server_ips if _is_v4(ip)]
    lan = ",".join(n for n in settings.lan_networks if ":" not in n)
    found = tunnel_adapters()
    adapters = ",".join(f"'{name}'" for name in found) if found else ""

    commands = [
        # Clear whatever we left behind last time, so duplicate rules do not
        # pile up on every connection.
        f"Get-NetFirewallRule -DisplayName '{PREFIX}*' -ErrorAction SilentlyContinue "
        f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue",

        # The tunnel: the normal road. The adapters are looked up each time
        # rather than hard-coded — they differ per machine and per driver, and
        # they change when a second one is added.
        f"$tun = @({adapters}); if ($tun.Count) {{ "
        f"New-NetFirewallRule -DisplayName '{PREFIX}: tunnel' -Direction Outbound "
        f"-Action Allow -InterfaceAlias $tun -Profile Any | Out-Null }}",

        # Fallback for tunnel kinds that do report as remote access, such as
        # some WireGuard drivers.
        f"New-NetFirewallRule -DisplayName '{PREFIX}: tunnel type' -Direction Outbound "
        f"-Action Allow -InterfaceType RemoteAccess -Profile Any | Out-Null",

        # Local network: drives, printers, access from machines next to you.
        f"New-NetFirewallRule -DisplayName '{PREFIX}: local network' -Direction Outbound "
        f"-Action Allow -RemoteAddress {lan},255.255.255.255,224.0.0.0/4 -Profile Any | Out-Null",

        # Address assignment and name resolution inside the local network.
        f"New-NetFirewallRule -DisplayName '{PREFIX}: dhcp' -Direction Outbound "
        f"-Action Allow -Protocol UDP -RemotePort 67,68 -Profile Any | Out-Null",
    ]

    if v4:
        addresses = ",".join(v4)
        commands.append(
            f"New-NetFirewallRule -DisplayName '{PREFIX}: vpn servers' -Direction Outbound "
            f"-Action Allow -RemoteAddress {addresses} -Profile Any | Out-Null"
        )

    if settings.block_ipv6:
        # IPv6 does not go through the provider's tunnel, so every routable
        # address is a leak.
        #
        # The range is written as "2000::/3" and not "::/0": the Windows
        # firewall rejects the latter as an invalid prefix. The former covers
        # exactly the publicly routable addresses, leaving out the local
        # network — which we want to stay reachable anyway.
        commands.append(
            f"New-NetFirewallRule -DisplayName '{PREFIX}: block ipv6' -Direction Outbound "
            f"-Action Block -RemoteAddress 2000::/3 -Profile Any | Out-Null"
        )

    # The default comes last, once the exceptions exist: applied first, it
    # would cut the connection the remaining rules are set up over.
    commands.append(
        f"Set-NetFirewallProfile -Profile {','.join(PROFILES)} "
        f"-DefaultOutboundAction Block -Enabled True"
    )
    return commands


def _is_v4(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr.split("/")[0]),
                          ipaddress.IPv4Address)
    except ValueError:
        return True


# ── lifecycle ─────────────────────────────────────────────────────────────


def _save_previous() -> None:
    """Keeps the default outbound action, for restoring later."""
    out = _ps(
        f"Get-NetFirewallProfile -Profile {','.join(PROFILES)} "
        f"| Select-Object Name,DefaultOutboundAction,Enabled | ConvertTo-Json",
        check=False,
    ).stdout.strip()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_FILE.write_text(out or "[]", encoding="utf-8")


def apply(settings, server_ips: list[str] | None = None,
          grace_seconds: int | None = None, self_path: str | None = None) -> None:
    """Same signature as on Linux. The rollback timer is not used here: the
    rules go in incrementally and the last one — the "block" default — is what
    closes the network. If anything fails before it, the machine has not lost
    its connection."""
    _save_previous()
    commands = _rules(settings, server_ips or [])

    # The rules go in first and the "block" default last. If a rule fails we
    # stop BEFORE the network closes and clean up: a half-built firewall would
    # cut traffic that should pass, without saying so anywhere.
    for command in commands[:-1]:
        result = _ps(command, check=False)
        if result.returncode != 0 and "Remove-NetFirewallRule" not in command:
            teardown()
            raise FirewallError(
                (result.stderr.strip().splitlines() or ["unknown error"])[0]
            )

    result = _ps(commands[-1], check=False)
    if result.returncode != 0:
        teardown()
        raise FirewallError("The default outbound block was not applied.")
    publish_state()


def teardown() -> None:
    """Removes our rules and restores the default."""
    _ps(f"Get-NetFirewallRule -DisplayName '{PREFIX}*' -ErrorAction SilentlyContinue "
        f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue", check=False)

    # Restore to "Allow": it is the Windows default and the safe state when
    # there is no protection — otherwise the machine would be left without a
    # network after uninstalling.
    previous = "Allow"
    try:
        saved = json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
        entries = saved if isinstance(saved, list) else [saved]
        actions = {e.get("DefaultOutboundAction") for e in entries}
        if actions == {2} or actions == {"Block"}:
            previous = "Allow"          # it was already closed by us
    except (FileNotFoundError, json.JSONDecodeError, AttributeError):
        pass

    _ps(f"Set-NetFirewallProfile -Profile {','.join(PROFILES)} "
        f"-DefaultOutboundAction {previous}", check=False)
    publish_state()


rollback = teardown          # on Windows rolling back is the same action


def is_active() -> bool:
    try:
        return bool(json.loads(STATUS_FILE.read_text(encoding="utf-8")).get("active"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return _probe_active()


def _probe_active() -> bool:
    out = _ps(f"(Get-NetFirewallRule -DisplayName '{PREFIX}*' "
              f"-ErrorAction SilentlyContinue | Measure-Object).Count", check=False).stdout
    return out.strip().isdigit() and int(out.strip()) > 0


def publish_state() -> None:
    """Publishes the state so an ordinary user can read it too.

    The GUI runs without administrator rights and cannot ask the firewall
    directly; without this file it would show "off" while everything works.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"active": _probe_active(), "counters": {}}
    STATUS_FILE.write_text(json.dumps(payload), encoding="utf-8")


def cache_servers(ips: list[str]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        CACHED_IPS.write_text(json.dumps(sorted(set(ips))), encoding="utf-8")
    except OSError:
        pass


def cached_servers() -> list[str]:
    try:
        return json.loads(CACHED_IPS.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def blocked_counters() -> dict[str, int]:
    """Windows does not count packets per rule without logging enabled."""
    return {}


def update_server_ips(ips: list[str]) -> None:
    """Refreshes only the servers rule, without rebuilding the rest."""
    v4 = [ip for ip in ips if _is_v4(ip)]
    if not v4:
        return
    _ps(f"Get-NetFirewallRule -DisplayName '{PREFIX}: vpn servers' "
        f"-ErrorAction SilentlyContinue | Remove-NetFirewallRule "
        f"-ErrorAction SilentlyContinue", check=False)
    _ps(f"New-NetFirewallRule -DisplayName '{PREFIX}: vpn servers' -Direction Outbound "
        f"-Action Allow -RemoteAddress {','.join(v4)} -Profile Any | Out-Null", check=False)
    cache_servers(ips)
