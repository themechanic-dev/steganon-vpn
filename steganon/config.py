"""Steganon's settings.

The locations' priority order lives here rather than in the code: it is the
main thing the user changes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

def _default_dirs() -> tuple[Path, Path]:
    """Where the settings and the transient state live, per system.

    On Linux the transient state goes to memory (`/run`) and is lost at boot —
    which is right, because it describes the current session. Windows has no
    equivalent, so it sits next to the settings.
    """
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Steganon"
        return base, base
    return Path("/etc/steganon"), Path("/run/steganon")


_config_default, _runtime_default = _default_dirs()

CONFIG_DIR = Path(os.environ.get("STEGANON_CONFIG_DIR", _config_default))
CONFIG_FILE = CONFIG_DIR / "config.json"
PROFILE_DIR = CONFIG_DIR / "profiles"
RUNTIME_DIR = Path(os.environ.get("STEGANON_RUNTIME_DIR", _runtime_default))


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Runs a command without flashing a console window.

    On Windows every call to an external program opens its own window by
    default. The GUI checks state every few seconds, and each check asks the
    system about interfaces and routes — the result was windows blinking on
    and off the screen continuously. The flag keeps them invisible; on Linux
    there is no such problem and the argument is ignored.
    """
    if sys.platform.startswith("win"):
        kwargs.setdefault("creationflags", 0)
        kwargs["creationflags"] |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(command, **kwargs)


def restrict(path: Path) -> None:
    """Restricts a file so only the administrator can read it.

    The two systems do this completely differently. On Linux the file's
    permission bits are enough. On Windows "chmod" exists but is close to
    decorative: the real permissions live in an access control list, and
    without breaking inheritance the file stays readable by every user of the
    machine. This covers private keys and credentials, so the difference is
    not theoretical.
    """
    if sys.platform.startswith("win"):
        # A clean permission list is built from scratch, rather than removing
        # entries one by one.
        #
        # The reason: breaking inheritance removes only what comes from the
        # parent folder; the file's creator keeps an explicit right of its own
        # that survives. A file that looks "locked down" therefore stays
        # readable by the account that wrote it. This covers private keys and
        # passwords, so the difference is not theoretical.
        #
        # With a clean list there is no need to guess who has access: we state
        # explicitly who does, and nobody else has any.
        script = f"""
$path = '{path}'
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
$admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
foreach ($sid in @($admins, $system)) {{
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'Allow')))
}}
$acl.SetOwner($admins)
Set-Acl -Path $path -AclObject $acl
"""
        run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        return

    try:
        path.chmod(0o600)
    except OSError:
        pass


def readable(path: Path) -> None:
    """Makes a file readable by an ordinary user.

    Needed for anything the GUI reads, since it runs without privileges. On
    Windows inheritance already covers it, so nothing happens.
    """
    if sys.platform.startswith("win"):
        return
    try:
        path.chmod(0o644)
    except OSError:
        pass


def autostart_active() -> bool:
    """Whether protection really does start at boot.

    Asks the system, not the settings file. The settings carry the user's
    intent and default to true; the services are what actually decide. Showing
    the intent as though it were the state told the user they were covered
    after a reboot when nothing had been enabled — the exact kind of lie a
    security tool must never tell, and in the reassuring direction, which is
    the worse one.
    """
    from . import backends
    try:
        return backends.service().autostart_enabled()
    except Exception:
        return False


def pretty(name: str) -> str:
    """A location name tidied for display.

    The name belongs to the user — they chose it when importing the profile.
    We only replace separators and fix the case, and we never translate it:
    there is no list of "known" countries anywhere in this program, so no
    place is treated as more expected than another.
    """
    clean = name.replace("-", " ").replace("_", " ").strip()
    return clean.upper() if len(clean) <= 3 else clean.title()


def flag_for(code: str) -> str:
    """A flag emoji from an ISO 3166-1 alpha-2 code, or a neutral globe.

    Built from the two letters arithmetically rather than looked up, so every
    country works and the program carries no table of them.
    """
    code = (code or "").strip()
    if len(code) == 2 and code.isalpha():
        return chr(0x1F1E6 + ord(code[0].upper()) - 65) + \
               chr(0x1F1E6 + ord(code[1].upper()) - 65)
    return "\U0001F310"


@dataclass
class Location:
    """One VPN location: a name, a server, and its own folder of secrets.

    Everything belonging to a location lives in that one folder — certificates
    and credentials alike. Providers do not agree on how they hand these out:
    some issue one username and password for the whole account, others a
    different pair per server. Keeping them per location covers both, and
    means removing a location removes its secrets with it.
    """

    name: str
    remote: str
    port: int = 443
    proto: str = "udp"
    certs: str = ""          # folder holding ca.crt / client.crt / client.key
    enabled: bool = True

    # ISO 3166-1 alpha-2, only ever used to draw a flag. Empty is fine.
    country: str = ""

    # Whether the provider's own .ovpn asked for a username and password.
    # Some setups authenticate with the certificate alone.
    needs_auth: bool = True

    @property
    def folder(self) -> Path:
        return Path(self.certs) if self.certs else PROFILE_DIR / self.name

    @property
    def credentials(self) -> Path:
        """This location's own username and password."""
        return self.folder / "credentials"

    @property
    def has_credentials(self) -> bool:
        return self.credentials.exists()

    @property
    def label(self) -> str:
        return pretty(self.name)

    @property
    def flag(self) -> str:
        return flag_for(self.country)


@dataclass
class Settings:
    # The order locations are tried in. First = preferred.
    locations: list[Location] = field(default_factory=list)

    # Networks that stay reachable outside the tunnel. Without them you lose
    # network drives, printers and access from machines next to you.
    lan_networks: list[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )

    # How long the guard waits before rolling back, when rules change.
    rollback_grace_seconds: int = 60

    # How often the connection's health is checked.
    health_interval_seconds: int = 20

    # How many consecutive failures before switching location.
    failures_before_switch: int = 3

    # Above this threshold the connection is called slow. It is not a failure
    # — just a remark. The threshold is generous on purpose: the measurement
    # includes name resolution and a TLS handshake, and on a satellite link
    # three seconds is normal.
    latency_threshold_ms: int = 4000

    # Whether IPv6 is blocked entirely outside the local network.
    block_ipv6: bool = True

    # Whether the tunnel comes up automatically at boot.
    autostart: bool = True

    # Interface language. Empty = follow the system.
    language: str = ""

    def enabled_locations(self) -> list[Location]:
        return [loc for loc in self.locations if loc.enabled]

    def find(self, name: str) -> Location | None:
        return next((loc for loc in self.locations if loc.name == name), None)

    # ── persistence ───────────────────────────────────────────────────────

    def save(self, path: Path = CONFIG_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(self)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        # World readable: the GUI runs without privileges and without this it
        # sees an empty location list — apparently "no connection" while
        # everything works. It holds no secrets; those live separately.
        readable(path)

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> "Settings":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        locs = [Location(**item) for item in raw.pop("locations", [])]
        return cls(locations=locs, **raw)

    # ── reordering ────────────────────────────────────────────────────────

    def move(self, name: str, delta: int) -> bool:
        """Moves a location up or down the priority order."""
        names = [loc.name for loc in self.locations]
        if name not in names:
            return False
        i = names.index(name)
        j = max(0, min(len(self.locations) - 1, i + delta))
        if i == j:
            return False
        self.locations.insert(j, self.locations.pop(i))
        return True

    def reorder(self, order: list[str]) -> None:
        """Sets the order explicitly. Anything unmentioned goes to the end."""
        index = {name: pos for pos, name in enumerate(order)}
        self.locations.sort(key=lambda loc: index.get(loc.name, len(order)))
