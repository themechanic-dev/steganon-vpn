"""The command line.

Covers everything without a GUI: the GUI is a front end over this. A security
tool has to work on a machine with no screen.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
import time

from . import backends, firewall, monitor, profiles, tunnel
from .config import CONFIG_FILE, Location, Settings, restrict, run

def _colours() -> tuple[str, ...]:
    """Colours only where they render.

    Two cases rule them out. When output is not going to a terminal — piped to
    a file or read by another program — the codes would show up as garbage in
    the text. And the classic Windows console does not interpret them at all
    unless explicitly asked to.
    """
    if not sys.stdout.isatty():
        return ("",) * 6

    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            handle = kernel.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel.GetConsoleMode(handle, ctypes.byref(mode))
            # 0x0004 = process control sequences on output
            if not kernel.SetConsoleMode(handle, mode.value | 0x0004):
                return ("",) * 6
        except (AttributeError, OSError):
            return ("",) * 6

    return ("\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")


GREEN, RED, YELLOW, DIM, BOLD, OFF = _colours()


def is_elevated() -> bool:
    """Are we running with administrator rights?

    The two systems answer differently: Linux has a numeric user id, Windows a
    property of the security token. "os.geteuid" does not even exist on
    Windows and raises.
    """
    if sys.platform.startswith("win"):
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def need_root() -> None:
    if not is_elevated():
        if sys.platform.startswith("win"):
            sys.exit("Administrator rights are required. Open the command "
                     "prompt with right click → “Run as administrator”.")
        sys.exit("Administrator rights are required.")


def mark(ok: bool) -> str:
    return f"{GREEN}✓{OFF}" if ok else f"{RED}✗{OFF}"


# ── commands ──────────────────────────────────────────────────────────────


def cmd_status(settings: Settings, args) -> int:
    h = monitor.check(settings)
    active = firewall.is_active()

    print(f"\n  {BOLD}Steganon{OFF}\n")
    print(f"  {mark(active)} Firewall       {'on' if active else 'off'}")
    print(f"  {mark(h.interface_up)} Tunnel         {tunnel.tunnel_interface() or '—'}")
    print(f"  {mark(h.owned)} Control        {'Steganon' if h.owned else 'someone else'}")
    print(f"  {mark(h.routed)} Routing        {'through the tunnel' if h.routed else 'OUTSIDE the tunnel'}")
    print(f"  {mark(h.reachable)} Connectivity   {f'{h.latency_ms:.0f} ms' if h.latency_ms else '—'}")
    print(f"  {mark(h.identity_ok)} Identity       {h.external_ip or '—'}")

    server = tunnel.current_server()
    if server:
        print(f"\n  {DIM}Server:{OFF} {server}")
    if h.detail:
        colour = RED if not h.healthy else YELLOW
        print(f"  {colour}{h.detail}{OFF}")

    counters = firewall.blocked_counters()
    if counters:
        parts = ", ".join(f"{v} {k}" for k, v in counters.items())
        print(f"  {DIM}Blocked: {parts} packets{OFF}")

    print(f"\n  {DIM}Priority order:{OFF}")
    for i, loc in enumerate(settings.locations, 1):
        state = "" if loc.enabled else f" {DIM}(disabled){OFF}"
        # A location that needs a password and has none will fail the moment
        # it is tried, so it is worth saying now rather than at 3am.
        if loc.needs_auth and not loc.has_credentials:
            state += f" {YELLOW}(no credentials){OFF}"
        print(f"    {i}. {loc.flag} {loc.label}{state}")
    print()
    return 0 if h.healthy else 1


def cmd_up(settings: Settings, args) -> int:
    need_root()

    usable = settings.enabled_locations()
    if not usable:
        sys.exit("No enabled location. Add one with: steganon add <path>")

    # Each location carries its own credentials, so they are checked one by
    # one. The first is fatal — it is what we are about to connect with. The
    # rest are a warning: failover would skip them, and finding that out
    # during an outage is worse than hearing it now.
    first = usable[0]
    if first.needs_auth and not first.has_credentials:
        sys.exit(f"{first.label} has no credentials yet. Set them with:\n"
                 f"  steganon credentials {first.name}")
    starved = [loc.name for loc in usable[1:]
               if loc.needs_auth and not loc.has_credentials]
    if starved:
        print(f"  {YELLOW}No credentials for: {', '.join(starved)} — "
              f"failover will skip them.{OFF}")

    # The address without a tunnel is recorded now, while it is still visible.
    real = monitor.remember_real_ip()
    if real:
        print(f"  {DIM}Unprotected address: {real}{OFF}")

    # Servers are resolved while there is still a network — after the firewall
    # goes up there may not be one.
    print("  Looking up server addresses…")
    ips = firewall.resolve_servers(settings)
    if not ips:
        sys.exit("No server address could be resolved. Check your connection.")
    print(f"  {DIM}Found {len(ips)} addresses.{OFF}")
    firewall.cache_servers(ips)

    print("  Applying the firewall…")
    grace = 0 if args.no_grace else settings.rollback_grace_seconds
    firewall.apply(settings, ips, grace_seconds=grace, self_path=sys.argv[0])

    print("  Connecting…")
    ok, message = tunnel.start(settings)
    print(f"  {message}")

    if not ok:
        print(f"  {RED}Connection failed — rolling the firewall back.{OFF}")
        firewall.rollback()
        return 1

    h = monitor.check(settings)
    if h.healthy:
        if grace:
            firewall.confirm()
        print(f"  {GREEN}Ready.{OFF} Outbound address: {h.external_ip}")
        return 0

    print(f"  {RED}Verification failed: {h.detail}{OFF}")
    tunnel.stop()
    firewall.rollback()
    return 1


def cmd_down(settings: Settings, args) -> int:
    need_root()

    # The order of the three steps is not arbitrary.

    # 1. The supervisor stops first. Otherwise it would see the connection drop,
    #    read it as a failure and bring it straight back up.
    if getattr(args, "service", False):
        print("  Stopping the service…")
        backends.service().stop()
        if getattr(args, "permanent", False):
            backends.service().set_autostart(False)

    # 2. Then a clean disconnect: SIGTERM triggers "explicit-exit-notify",
    #    which tells the server rather than letting the session time out.
    print("  Disconnecting…")
    tunnel.stop()

    # 3. The firewall last. While the tunnel comes down the rules stay in
    #    force, so there is never a moment with an open network and no
    #    protection. The reverse order would leave a leak window.
    print("  Removing the firewall…")
    firewall.teardown()

    if getattr(args, "permanent", False):
        print(f"  {YELLOW}They will not start on the next boot either.{OFF}")
    print(f"  {YELLOW}Traffic now leaves unprotected.{OFF}")
    return 0


def cmd_watch(settings: Settings, args) -> int:
    """The supervision loop — this is what runs as a service."""
    need_root()

    # The connection is made here rather than in a preparatory step, so that
    # OpenVPN belongs to the same process as the supervisor. When it started
    # earlier it was left orphaned in the service's control group and systemd
    # reported an unclean exit on every restart.
    if getattr(args, "connect", False):
        rc = cmd_up(settings, argparse.Namespace(no_grace=True))
        if rc != 0:
            print(f"  {YELLOW}The first connection failed — the supervisor "
                  f"will try the remaining locations.{OFF}")

    failures = 0
    print("  Supervisor started.")
    while True:
        h = monitor.check(settings)
        monitor.save_state({
            "healthy": h.healthy, "ip": h.external_ip,
            "server": tunnel.current_server(), "detail": h.detail,
            "latency_ms": h.latency_ms, "checked": time.time(),
        })

        if h.healthy:
            failures = 0
        else:
            failures += 1
            print(f"  {YELLOW}Failure {failures}/{settings.failures_before_switch}: {h.detail}{OFF}")
            if failures >= settings.failures_before_switch:
                print("  Switching location…")
                _rotate(settings)
                tunnel.stop()
                ok, msg = tunnel.start(settings)
                print(f"  {msg}")
                failures = 0

        time.sleep(settings.health_interval_seconds)


def _rotate(settings: Settings) -> None:
    """Moves the current first location to the end.

    It does not touch the settings file: the order the user chose stays the
    preference, and comes back on the next start.
    """
    enabled = settings.enabled_locations()
    if len(enabled) > 1:
        first = enabled[0]
        settings.locations.remove(first)
        settings.locations.append(first)


def cmd_order(settings: Settings, args) -> int:
    if args.set:
        settings.reorder(args.set)
    elif args.up:
        settings.move(args.up, -1)
    elif args.down:
        settings.move(args.down, +1)
    else:
        for i, loc in enumerate(settings.locations, 1):
            print(f"  {i}. {loc.name}")
        return 0
    settings.save()
    print("  Order saved:")
    for i, loc in enumerate(settings.locations, 1):
        print(f"    {i}. {loc.name}")
    return 0


def cmd_latency(settings: Settings, args) -> int:
    print("\n  Latency per location:\n")
    for name, ms in monitor.rank_locations(settings):
        bar = "█" * min(40, int((ms or 0) / 10)) if ms else ""
        value = f"{ms:6.1f} ms" if ms else "     —   "
        print(f"    {name:<14} {value}  {DIM}{bar}{OFF}")
    print(f"\n  {DIM}The order does not change on its own — it is yours.{OFF}\n")
    return 0


def cmd_firewall(settings: Settings, args) -> int:
    need_root()
    if args.action in ("boot", "reapply"):
        # Runs before the network comes up. It uses the cached addresses:
        # name resolution would fail here, and without an exception for the
        # servers the firewall would block the very connection about to be
        # established.
        # "reapply" is the same operation under a name that says what it is
        # for: rebuilding the rules after a setting changed, while the
        # protection is already up. Without it, turning IPv6 blocking on would
        # be recorded in the settings and shown as on, while the running rules
        # still let IPv6 out.
        ips = firewall.cached_servers()
        firewall.apply(settings, ips)
        if ips:
            print(f"  Firewall on ({len(ips)} known servers).")
        else:
            print(f"  {YELLOW}Firewall on, with no known servers — "
                  f"the first connection will find them.{OFF}")
        return 0
    if args.action == "rollback":
        firewall.rollback()
        print("  Rolled back.")
    elif args.action == "confirm":
        print("  Confirmed." if firewall.confirm() else "  Nothing pending confirmation.")
    elif args.action == "show":
        print(firewall.current_ruleset())
    elif args.action == "off":
        firewall.teardown()
        print("  The firewall has been removed.")
    return 0


def cmd_add(settings: Settings, args) -> int:
    need_root()
    try:
        loc = profiles.add(settings, args.path, args.name, args.country)
    except profiles.ImportError_ as exc:
        sys.exit(f"  {RED}{exc}{OFF}")
    settings.save()

    print(f"  {GREEN}Added:{OFF} {loc.flag} {loc.label} → "
          f"{loc.remote}:{loc.port} ({loc.proto})")
    print(f"  {DIM}Position in the order: {len(settings.locations)}{OFF}")
    if loc.country and not args.country:
        print(f"  {DIM}Country guessed as \u201c{loc.country}\u201d — "
              f"use --country to correct the flag.{OFF}")

    _sync_firewall(settings)

    if loc.needs_auth:
        print(f"\n  This location needs its own username and password:")
        print(f"    steganon credentials {loc.name}")
    else:
        print(f"\n  {DIM}No username needed — it authenticates with the "
              f"certificate.{OFF}")
    return 0


def _sync_firewall(settings: Settings) -> None:
    """Teaches the running firewall about the current set of servers.

    Without this, a location added while the protection is up cannot be
    reached: the firewall only permits the addresses it was given when it was
    applied, and the new server is not among them. The failure would look like
    a dead provider rather than a rule we forgot to update.
    """
    if not firewall.is_active():
        return
    ips = firewall.resolve_servers(settings)
    if not ips:
        print(f"  {YELLOW}Could not resolve the servers — the firewall still "
              f"has the old list.{OFF}")
        return
    firewall.update_server_ips(ips)
    firewall.cache_servers(ips)
    print(f"  {DIM}Firewall updated: {len(ips)} server addresses allowed.{OFF}")


def cmd_remove(settings: Settings, args) -> int:
    need_root()
    try:
        ok = profiles.remove(settings, args.name, delete_files=not args.keep_files)
    except profiles.ImportError_ as exc:
        sys.exit(f"  {RED}{exc}{OFF}")
    if not ok:
        sys.exit(f"  No location named “{args.name}”.")
    settings.save()
    print(f"  Removed: {args.name}")
    _sync_firewall(settings)
    return 0


def cmd_inspect(settings: Settings, args) -> int:
    """Shows what would be imported, without changing anything."""
    try:
        info = profiles.inspect(args.path)
    except profiles.ImportError_ as exc:
        sys.exit(f"  {RED}{exc}{OFF}")
    print(f"\n  file:          {info['ovpn']}")
    print(f"  server:        {info['remote']}:{info['port']} ({info['proto']})")
    print(f"  certificates:  {'embedded' if info['inline'] else 'separate files'}")
    print(f"  credentials:   {'username and password needed' if info['auth'] else 'certificate only'}")
    print(f"  country guess: {info['country'] or '(none — pass --country)'}")
    print(f"  name:          {info['name']}\n")
    return 0


def cmd_credentials(settings: Settings, args) -> int:
    """Stores one location's username and password.

    Per location, not per installation. Providers do not agree: some issue a
    single pair for the account, others a different one per server. Storing
    them beside the location's certificates covers both without asking the
    user which kind they have — and removing a location takes its secrets
    with it.

    Input is read from the terminal rather than from an argument: anything
    typed on a command line is visible to every user of the machine through
    the process list.
    """
    need_root()

    location = settings.find(args.location)
    if location is None:
        known = ", ".join(loc.name for loc in settings.locations) or "none yet"
        sys.exit(f"  No location named \u201c{args.location}\u201d. Known: {known}")

    if args.stdin:
        lines = sys.stdin.read().splitlines()
        if len(lines) < 2 or not lines[0].strip() or not lines[1]:
            sys.exit("  Expected two lines: username and password.")
        username, password = lines[0].strip(), lines[1]
    else:
        import getpass
        print(f"  Credentials for {location.flag} {location.label} "
              f"({location.remote})")
        username = input("  Username: ").strip()
        password = getpass.getpass("  Password: ")
        if not username or not password:
            sys.exit("  Both are required.")

    target = location.credentials
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"{username}\n{password}\n", encoding="utf-8")
    restrict(target)
    print(f"  {GREEN}Saved{OFF} for {location.flag} {location.label} "
          f"(administrator only).")
    return 0


def cmd_autostart(settings: Settings, args) -> int:
    """Turns automatic start of the protection on or off."""
    need_root()
    enable = args.state == "on"
    backends.service().set_autostart(enable)

    # And the window too, so the icon appears in the tray. It is one decision
    # for the user, so one command sets it — even though the two pieces live
    # in different places on the system.
    service = backends.service()
    if hasattr(service, "set_gui_autostart"):
        service.set_gui_autostart(enable)
    else:
        from . import prefs
        prefs.set_autostart(enable)

    settings.autostart = enable
    settings.save()
    if enable:
        print(f"  {GREEN}Protection will start on its own.{OFF}")
    else:
        print(f"  {YELLOW}It will not start at boot — you will need "
              f"“steganon up” each time.{OFF}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="steganon",
                                description="Steganon — VPN with a kill switch and failover")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="what is true right now")

    up = sub.add_parser("up", help="firewall and connection")
    up.add_argument("--no-grace", action="store_true",
                    help="no rollback timer (service use only)")

    d = sub.add_parser("down", help="disconnect and remove the firewall")
    d.add_argument("--service", action="store_true",
                   help="stop the service too, or it will reconnect")
    d.add_argument("--permanent", action="store_true",
                   help="do not start on the next boot either")
    w = sub.add_parser("watch", help="supervision loop")
    w.add_argument("--connect", action="store_true",
                   help="connect before supervising (for the service)")
    sub.add_parser("latency", help="measure latency per location")

    o = sub.add_parser("order", help="priority order")
    o.add_argument("--set", nargs="+", metavar="NAME")
    o.add_argument("--up", metavar="NAME")
    o.add_argument("--down", metavar="NAME")

    a = sub.add_parser("add", help="add a location from a .ovpn file")
    a.add_argument("path", type=Path, metavar="PATH")
    a.add_argument("--name", help="name (guessed otherwise)")
    a.add_argument("--country", metavar="XX",
                   help="two-letter country code, for the flag only")

    r = sub.add_parser("remove", help="remove a location")
    r.add_argument("name", metavar="NAME")
    r.add_argument("--keep-files", action="store_true", help="keep the certificates")

    a2 = sub.add_parser("autostart", help="start at boot or not")
    a2.add_argument("state", choices=["on", "off"])

    c = sub.add_parser("credentials", help="one location's username and password")
    c.add_argument("location", metavar="NAME",
                   help="which location these belong to")
    c.add_argument("--stdin", action="store_true",
                   help="read two lines from standard input")

    i = sub.add_parser("inspect", help="what a .ovpn file contains")
    i.add_argument("path", type=Path, metavar="PATH")

    f = sub.add_parser("firewall", help="firewall control")
    f.add_argument("action",
                   choices=["boot", "reapply", "show", "confirm", "rollback", "off"])

    return p


def _prepare_console() -> None:
    """Lets the console print anything that is not Latin.

    The Windows console uses a code page that does not include Greek
    characters: every message from the application would end in an encoding
    error instead of being shown. This is set here rather than through an
    environment variable, so it holds whoever invokes the command.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            # line_buffering matters for the supervisor. Python buffers output
            # in blocks when it is not writing to a terminal, and the service
            # writes to the journal — so every "failure 2/3" and every
            # location switch sat in memory instead of being recorded, and a
            # failover left no trace at all. Line buffering costs nothing at
            # this volume and makes the log honest.
            stream.reconfigure(encoding="utf-8", errors="replace",
                               line_buffering=True)
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _prepare_console()
    args = build_parser().parse_args(argv)
    settings = Settings.load()

    if not settings.locations and args.command not in ("firewall", "add", "inspect", "credentials", "autostart"):
        sys.exit(f"No locations yet ({CONFIG_FILE}).\n"
                 f"Add one with: steganon add <folder-or-file.ovpn>")

    handlers = {
        "status": cmd_status, "up": cmd_up, "down": cmd_down,
        "watch": cmd_watch, "order": cmd_order, "latency": cmd_latency,
        "firewall": cmd_firewall, "add": cmd_add, "remove": cmd_remove,
        "inspect": cmd_inspect, "credentials": cmd_credentials,
        "autostart": cmd_autostart,
    }
    try:
        return handlers[args.command](settings, args)
    except KeyboardInterrupt:
        return 130
    except (firewall.FirewallError, tunnel.TunnelError) as exc:
        sys.exit(f"  {RED}{exc}{OFF}")


if __name__ == "__main__":
    sys.exit(main())
