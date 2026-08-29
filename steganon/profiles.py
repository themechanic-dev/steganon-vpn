"""Importing and removing locations.

Accepts whatever providers hand out: either a folder with the config file and
the certificates beside it, or a self-contained .ovpn with everything inline.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

from .config import Location, PROFILE_DIR, Settings, readable, restrict

REMOTE = re.compile(r"^\s*remote\s+(\S+)(?:\s+(\d+))?(?:\s+(udp|tcp))?", re.M)
INLINE = re.compile(r"<(ca|cert|key)>(.*?)</\1>", re.S)
AUTH = re.compile(r"^\s*auth-user-pass\b", re.M)
CODE = re.compile(r"^([a-z]{2})\d*$")


class ImportError_(ValueError):
    """The file cannot be used."""


def _slug(text: str) -> str:
    """A name that also works as a folder, with no surprises."""
    clean = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return clean or "location"


def guess_name(ovpn: Path, remote: str) -> str:
    """Guesses a location name from the folder or the server address."""
    parent = ovpn.parent.name
    if parent and parent not in ("profiles", "vpn", "openvpn", "config", "tmp"):
        return _slug(re.sub(r"[-_]?openvpn$", "", parent))
    # e.g. 12-3-gr.example.net → gr
    head = remote.split(".")[0]
    return _slug(head.split("-")[-1] if "-" in head else head)


def guess_country(name: str, remote: str) -> str:
    """Guesses an ISO 3166-1 alpha-2 code, for the flag only.

    Providers usually put the country in the host name — "12-3-gr.example.net",
    "us-east.example.com", "nl3.example.net". We look at the first and last
    token of the first label and take it if it reads as two letters.

    This is a guess and it says so: `add` prints the flag it chose, and
    `--country` overrides it. Nothing depends on it working — a wrong or empty
    code costs a flag, not a connection.
    """
    if len(name) == 2 and name.isalpha():
        return name.lower()
    tokens = re.split(r"[-_]", remote.split(".")[0].lower())
    for token in (tokens[-1], tokens[0]):
        match = CODE.fullmatch(token)
        if match:
            return match.group(1)
    return ""


def inspect(path: Path) -> dict:
    """Reads a .ovpn and reports what it found, changing nothing."""
    if path.is_dir():
        candidates = sorted(path.glob("*.ovpn")) or sorted(path.glob("*.conf"))
        if not candidates:
            raise ImportError_(f"No .ovpn file found in {path}")
        path = candidates[0]

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ImportError_(f"Cannot be read: {exc}") from exc

    match = REMOTE.search(text)
    if not match:
        raise ImportError_("The file defines no server (no \u201cremote\u201d line).")

    remote, port, proto = match.group(1), match.group(2) or "443", match.group(3) or "udp"
    inline = {tag for tag, _body in INLINE.findall(text)}
    folder = path.parent
    external = {
        name: folder / fname
        for name, fname in (("ca", "ca.crt"), ("cert", "client.crt"), ("key", "client.key"))
        if (folder / fname).exists()
    }

    missing = [n for n in ("ca", "cert", "key") if n not in inline and n not in external]
    if missing:
        raise ImportError_(
            "Missing certificates: " + ", ".join(missing) +
            ". They must be either inline in the .ovpn or beside it as "
            "ca.crt/client.crt/client.key."
        )

    name = guess_name(path, remote)
    return {
        "ovpn": path, "remote": remote, "port": int(port), "proto": proto,
        "inline": bool(inline), "external": external,
        "name": name,
        # Whether the provider's file asks for a username and password at all.
        # Certificate-only setups exist, and must not be nagged for one.
        "auth": bool(AUTH.search(text)),
        "country": guess_country(name, remote),
    }


def add(settings: Settings, source: Path, name: str | None = None,
        country: str | None = None) -> Location:
    """Imports a location. Returns the object that was added."""
    info = inspect(Path(source))
    final = _slug(name or info["name"])

    if any(loc.name == final for loc in settings.locations):
        raise ImportError_(f"A location named \u201c{final}\u201d already exists.")

    target = PROFILE_DIR / final
    target.mkdir(parents=True, exist_ok=True)
    # The folder and the certificates are read by the GUI, which runs without
    # privileges. The private key is not — it gets a strict permission below,
    # as soon as it is written.
    if not sys.platform.startswith("win"):
        target.chmod(0o755)

    if info["external"]:
        for key, path in info["external"].items():
            shutil.copy2(path, target / {"ca": "ca.crt", "cert": "client.crt",
                                         "key": "client.key"}[key])
    else:
        # Inline certificates are written out to separate files, so every
        # location has the same shape regardless of how it arrived.
        text = info["ovpn"].read_text(encoding="utf-8", errors="replace")
        for tag, body in INLINE.findall(text):
            fname = {"ca": "ca.crt", "cert": "client.crt", "key": "client.key"}[tag]
            (target / fname).write_text(body.strip() + "\n", encoding="utf-8")

    for cert_name in ("ca.crt", "client.crt"):
        if (target / cert_name).exists():
            readable(target / cert_name)
    restrict(target / "client.key")

    location = Location(name=final, remote=info["remote"], port=info["port"],
                        proto=info["proto"], certs=str(target),
                        country=(country or info["country"] or "").lower(),
                        needs_auth=info["auth"])
    settings.locations.append(location)
    return location


def remove(settings: Settings, name: str, delete_files: bool = True) -> bool:
    """Removes a location. Refuses to leave the list empty."""
    match = next((loc for loc in settings.locations if loc.name == name), None)
    if match is None:
        return False
    if len(settings.locations) <= 1:
        raise ImportError_("The last location cannot be removed.")

    settings.locations.remove(match)
    if delete_files and match.certs:
        folder = Path(match.certs)
        # Safety catch: we only delete from inside our own profile folder.
        if folder.is_dir() and folder.parent == PROFILE_DIR:
            shutil.rmtree(folder, ignore_errors=True)
    return True
