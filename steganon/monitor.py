"""The supervisor.

A tunnel existing proves nothing: it can be up and carry no traffic at all.
So the check runs at four levels, cheapest to most expensive, and stops at the
first one that fails.

The identity check asks "is my outbound address different from my real one?"
and not "am I in the right country?". Geolocation databases disagree with each
other — the same address showed up as Athens from two services and as Czechia
from a third. "It is not mine" is a fact; "it is in Greece" is an opinion.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import tunnel
from .config import RUNTIME_DIR, Settings, run

REAL_IP_FILE = RUNTIME_DIR / "real_ip"
STATE_FILE = RUNTIME_DIR / "state.json"

# Sources for the outbound address. More than one, because a temporary
# failure at a single service must not look like the tunnel going down.
IP_SOURCES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


@dataclass
class Health:
    owned: bool = False
    interface_up: bool = False
    routed: bool = False
    reachable: bool = False
    identity_ok: bool = False
    latency_ms: float | None = None
    external_ip: str | None = None
    detail: str = ""

    @property
    def healthy(self) -> bool:
        return (self.owned and self.interface_up and self.routed
                and self.reachable and self.identity_ok)

    @property
    def foreign_tunnel(self) -> bool:
        """There is a tunnel and routing, but somebody else set it up."""
        return self.interface_up and self.routed and not self.owned


def _http_get(url: str, timeout: int = 8) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "steganon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace").strip()
    except Exception:
        return None


def external_ip(timeout: int = 8) -> str | None:
    for url in IP_SOURCES:
        value = _http_get(url, timeout)
        if value and len(value) < 64:
            return value
    return None


def remember_real_ip() -> str | None:
    """Records the address without a tunnel, so a leak can be recognised.

    Two cases where this must not even be attempted:

    With the tunnel up it would store the provider's address as the "real"
    one, and the leak check would be inverted.

    With the firewall up the outbound call is already blocked. The attempt
    would wait for every source to time out — long enough for the service to
    exceed its startup limit and fall into a restart loop. That is exactly how
    it showed up in the first reboot test: the firewall loaded first, and "up"
    hung on it.
    """
    from . import firewall
    if tunnel.routes_through_tunnel() or firewall.is_active():
        return known_real_ip()
    ip = external_ip()
    if ip:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        REAL_IP_FILE.write_text(ip, encoding="utf-8")
    return ip


def known_real_ip() -> str | None:
    try:
        return REAL_IP_FILE.read_text(encoding="utf-8").strip() or None
    except FileNotFoundError:
        return None


def check(settings: Settings) -> Health:
    h = Health()
    h.owned = tunnel.is_running()

    iface = tunnel.tunnel_interface()
    h.interface_up = iface is not None
    if not h.interface_up:
        h.detail = "No tunnel interface."
        return h

    h.routed = tunnel.routes_through_tunnel()
    if not h.routed:
        h.detail = "Internet traffic is not routed through the tunnel."
        return h

    if not h.owned:
        # The tunnel exists and routes, but something else set it up. Without
        # our own rules there is no guarantee against an IPv6 leak, nor any
        # about what happens if it drops.
        h.detail = "A VPN connection exists, but Steganon does not control it."
        return h

    started = time.time()
    ip = external_ip()
    h.latency_ms = round((time.time() - started) * 1000, 1)
    h.reachable = ip is not None
    h.external_ip = ip
    if not h.reachable:
        h.detail = "The tunnel is up but no traffic passes through it."
        return h

    if h.latency_ms and h.latency_ms > settings.latency_threshold_ms:
        h.detail = "Very slow response."

    real = known_real_ip()
    if real is None:
        # With no reference point we do not blame the connection; routing
        # through the tunnel has already been confirmed above.
        h.identity_ok = True
        h.detail = h.detail or "No reference address known."
    else:
        h.identity_ok = ip != real
        if not h.identity_ok:
            h.detail = "LEAK: the outbound address is your real one."

    return h


def ping_ms(host: str, count: int = 3) -> float | None:
    import sys as _sys
    flags = (["-n", str(count), "-w", "2000"] if _sys.platform.startswith("win")
             else ["-c", str(count), "-W", "2"])
    out = run(["ping", *flags, host]).stdout
    for line in out.splitlines():
        if "min/avg/max" in line:
            try:
                return float(line.split("=")[1].split("/")[1])
            except (IndexError, ValueError):
                return None
    return None


def rank_locations(settings: Settings) -> list[tuple[str, float | None]]:
    """Measures each location's latency. It does not reorder anything on its
    own — the order belongs to the user; this is information to decide with."""
    results = []
    for loc in settings.enabled_locations():
        results.append((loc.name, ping_ms(loc.remote)))
    return results


def save_state(payload: dict) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
