"""The firewall.

There is one principle: whatever is not explicitly allowed does not leave. The
default is "closed", so that every failure — of our code, of OpenVPN, of the
system — ends in "no network" and never in "no protection".

Every change goes through a guard: the rules are applied with a timer that
rolls them back unless they are confirmed. A wrong output rule also cuts the
connection you would fix it over — which is why the timer is armed before the
rules are applied, not after.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

from ..config import RUNTIME_DIR, Settings

TABLE = "steganon"
BACKUP = RUNTIME_DIR / "previous.nft"
PENDING = RUNTIME_DIR / "pending"
ROLLBACK_UNIT = "steganon-rollback"


class FirewallError(RuntimeError):
    pass


def _nft(*args: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["nft", *args], input=stdin, text=True, capture_output=True, check=check
    )


def available() -> bool:
    return shutil.which("nft") is not None


# ── generating the rules ──────────────────────────────────────────────────


def build_ruleset(settings: Settings, server_ips: list[str] | None = None) -> str:
    """Builds the complete rule set as text."""
    server_ips = server_ips or []
    v4 = sorted({ip for ip in server_ips if _is_v4(ip)})
    v6 = sorted({ip for ip in server_ips if not _is_v4(ip)})

    lan4 = [n for n in settings.lan_networks if ":" not in n]

    def elements(items: list[str]) -> str:
        return "elements = { " + ", ".join(items) + " }" if items else ""

    ipv6_policy = (
        '        # IPv6 does not go through the provider\'s tunnel, so every\n'
        '        # routable address is a leak. We keep only what the local\n'
        '        # network needs to work.\n'
        if settings.block_ipv6
        else "        # IPv6 allowed outside the tunnel — not recommended.\n        ip6 daddr ::/0 accept\n"
    )

    return f"""#!/usr/sbin/nft -f
# Generated automatically by Steganon. Manual edits are lost.

table inet {TABLE} {{

    # The VPN servers' addresses. They need an exception, or the firewall
    # blocks the very connection that brings the tunnel up.
    set vpn_servers {{
        type ipv4_addr
        flags interval
        auto-merge
        {elements(v4)}
    }}

    set vpn_servers6 {{
        type ipv6_addr
        flags interval
        auto-merge
        {elements(v6)}
    }}

    chain output {{
        type filter hook output priority filter
        policy drop

        # Replies on connections that have already passed the check.
        ct state established,related accept

        # Loopback never leaves the machine.
        oifname "lo" accept

        # The tunnel: the normal road for everything.
        oifname "tun*" accept
        oifname "wg*"  accept

        # Local network. Without this you lose network drives, printers and
        # access from machines next to you.
        ip daddr {{ {", ".join(lan4)} }} accept
        ip daddr 255.255.255.255 accept
        ip daddr 224.0.0.0/4 accept

{ipv6_policy}        ip6 daddr {{ fe80::/10, fc00::/7, ff00::/8 }} accept

        # Address assignment from the router.
        udp dport {{ 67, 68 }} accept

        # The VPN servers.
        ip  daddr @vpn_servers  accept
        ip6 daddr @vpn_servers6 accept

        # Whatever is left. We count before we drop, so it is visible what
        # was stopped — a silent firewall is impossible to debug.
        meta nfproto ipv6 counter comment "blocked IPv6"
        meta nfproto ipv4 counter comment "blocked IPv4"
        counter drop
    }}
}}
"""


def _is_v4(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr.split("/")[0]), ipaddress.IPv4Address)
    except ValueError:
        return True


CACHED_IPS = Path("/etc/steganon/server-ips.json")


def cache_servers(ips: list[str]) -> None:
    """Keeps the addresses for the next boot.

    At boot the firewall loads before the network, so there is no way to
    resolve the server names. Without cached addresses the rules would block
    the very connection that has to be established — and the machine would be
    left permanently without a network.
    """
    try:
        CACHED_IPS.parent.mkdir(parents=True, exist_ok=True)
        CACHED_IPS.write_text(json.dumps(sorted(set(ips))), encoding="utf-8")
        CACHED_IPS.chmod(0o644)
    except OSError:
        pass


def cached_servers() -> list[str]:
    try:
        return json.loads(CACHED_IPS.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def resolve_servers(settings: Settings) -> list[str]:
    """Resolves the server names to addresses.

    Done while there is still a network, because after the rules are applied
    name resolution may not be available — and then the firewall would block
    the very connection it is trying to restore.
    """
    found: list[str] = []
    for loc in settings.enabled_locations():
        try:
            for info in socket.getaddrinfo(loc.remote, loc.port, proto=socket.IPPROTO_UDP):
                found.append(info[4][0])
        except socket.gaierror:
            continue
    return sorted(set(found))


# ── applying, behind a guard ──────────────────────────────────────────────


def current_ruleset() -> str:
    try:
        return _nft("list", "ruleset").stdout
    except subprocess.CalledProcessError:
        return ""


def check_syntax(ruleset: str) -> tuple[bool, str]:
    proc = _nft("-c", "-f", "-", stdin=ruleset, check=False)
    return proc.returncode == 0, proc.stderr.strip()


def apply(settings: Settings, server_ips: list[str] | None = None,
          grace_seconds: int | None = None, self_path: str | None = None) -> None:
    """Applies the rules, with a rollback timer if a grace period is given.

    It takes settings and addresses — not ready-made rule text — so the
    signature matches the Windows implementation, where there is no "rule set"
    to produce up front.
    """
    ruleset = build_ruleset(settings, server_ips or [])
    ok, err = check_syntax(ruleset)
    if not ok:
        raise FirewallError(f"The rules do not pass the syntax check:\n{err}")

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP.write_text(current_ruleset(), encoding="utf-8")

    if grace_seconds:
        _arm_rollback(grace_seconds, self_path)

    _nft("flush", "ruleset")
    _nft("-f", "-", stdin=ruleset)
    publish_state()


def _arm_rollback(grace: int, self_path: str | None) -> None:
    subprocess.run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], capture_output=True)
    cmd = self_path or shutil.which("steganon") or "/usr/local/bin/steganon"
    subprocess.run(
        [
            "systemd-run", "--quiet",
            f"--on-active={grace}s",
            f"--unit={ROLLBACK_UNIT}",
            cmd, "firewall", "rollback",
        ],
        check=False, capture_output=True,
    )
    PENDING.write_text(str(grace), encoding="utf-8")


def confirm() -> bool:
    """Cancels the pending rollback. The rules stay."""
    if not PENDING.exists():
        return False
    subprocess.run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], capture_output=True)
    subprocess.run(["systemctl", "reset-failed", f"{ROLLBACK_UNIT}.timer"], capture_output=True)
    PENDING.unlink(missing_ok=True)
    return True


def rollback() -> None:
    """Restores the state that held before the last apply."""
    _nft("flush", "ruleset")
    if BACKUP.exists() and BACKUP.read_text(encoding="utf-8").strip():
        _nft("-f", str(BACKUP))
    PENDING.unlink(missing_ok=True)
    publish_state()


def teardown() -> None:
    """Removes the firewall entirely. Only used deliberately."""
    _nft("flush", "ruleset")
    PENDING.unlink(missing_ok=True)
    publish_state()


STATUS_FILE = RUNTIME_DIR / "firewall.json"


def publish_state() -> None:
    """Publishes the firewall's state so an ordinary user can read it too.

    "nft list ruleset" requires administrator rights. The GUI deliberately
    runs without them, so without this file it would get permission denied and
    read that as "firewall off" — that is, it would show less protection than
    there really is. In a security tool a lie in either direction erodes
    trust.
    """
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"active": TABLE in current_ruleset(), "counters": blocked_counters()}
    STATUS_FILE.write_text(json.dumps(payload), encoding="utf-8")
    STATUS_FILE.chmod(0o644)


def is_active() -> bool:
    """Is the firewall active? Works without privileges too."""
    if os.geteuid() == 0:
        return TABLE in current_ruleset()
    try:
        return bool(json.loads(STATUS_FILE.read_text(encoding="utf-8")).get("active"))
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def blocked_counters() -> dict[str, int]:
    """How many packets the firewall stopped, per address family."""
    if os.geteuid() != 0:
        try:
            return json.loads(STATUS_FILE.read_text(encoding="utf-8")).get("counters", {})
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    out = current_ruleset()
    counts: dict[str, int] = {}
    for line in out.splitlines():
        if "blocked" in line and "packets" in line:
            key = "IPv6" if "ipv6" in line else "IPv4"
            for part in line.split():
                if part.isdigit():
                    counts[key] = int(part)
                    break
    return counts


def update_server_ips(ips: list[str]) -> None:
    """Refreshes the set of allowed servers without a reload."""
    if not is_active():
        return
    v4 = [ip for ip in ips if _is_v4(ip)]
    v6 = [ip for ip in ips if not _is_v4(ip)]
    for name, items in (("vpn_servers", v4), ("vpn_servers6", v6)):
        _nft("flush", "set", "inet", TABLE, name, check=False)
        if items:
            _nft("add", "element", "inet", TABLE, name,
                 "{ " + ", ".join(items) + " }", check=False)
