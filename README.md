# Steganon

**All traffic through the tunnel, or none at all.**

A VPN manager for **Linux and Windows** that closes the network when there is
no protection, instead of leaving it open. Built on the tools every system
already has — it does not replace them, it orchestrates them.

> **Warning.** This tool changes the network rules of the **entire machine**.
> Once it is on, no traffic leaves outside the tunnel — apart from the local
> network. If something goes wrong you are left without internet until you fix
> it. **Try it in a virtual machine first.**

---

## Why it exists

A VPN that is "running" does not mean you are covered. Three things happen
silently in most setups:

**IPv6 bypasses the tunnel.** Most providers route IPv4 only. The network
interface keeps its own IPv6 address with a separate route, and every program
that prefers IPv6 — which is very nearly every browser — goes straight out.
Tested on a real connection: `curl -6` returned the ISP's address while the
VPN was up.

**There is no net when it drops.** If the tunnel is cut, traffic carries on
over the ordinary connection with no warning at all.

**There is a gap at boot.** In the first seconds of startup, services talk to
the outside before the VPN has had a chance to connect. Whatever leaves then,
leaves in the clear.

Steganon closes all three.

## What it does

- **Firewall closed by default** — it loads *before* the network on every
  boot. If the service fails to start, the machine is left without internet;
  that is the correct way for a security tool to fail.
- **Rollback guard** — every rule change undoes itself automatically after 60
  seconds unless it is confirmed. A wrong output rule also cuts the connection
  you would fix it over.
- **The local network stays reachable** — network drives, printers, virtual
  machines, SSH access from the machine next to you.
- **IPv6 blocked** outside the tunnel.
- **Automatic failover** to the next location when the current one stops
  responding, in an order you set.
- **Verification, not assumption** — a `tun0` interface existing is not
  enough. It checks that traffic really goes through it, that *this* tool
  brought the tunnel up, and that the outbound address is not your real one.
- **Graphical interface** in English and Greek, with a tray icon showing the
  country and the state.

## Requirements

**Linux**: `systemd`, `nftables`, `openvpn`. For the GUI, `python3-gi` with
GTK 4 and libadwaita. Tested on Ubuntu 26.04 with GNOME.

```bash
sudo apt install openvpn nftables python3-gi gir1.2-gtk-4.0 gir1.2-adw-1
```

**Windows**: 10 or 11. Nothing is needed up front — the installer brings
Python, OpenVPN and the GUI library itself.

## Installation

**Linux**

```bash
git clone https://github.com/themechanic-dev/steganon-vpn.git steganon && cd steganon
sudo ./install.sh
```

**Windows** — in PowerShell **as administrator**:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

### Adding your locations

The tool ships with **no servers, no countries and no provider** built in. You
add the profiles you have, one at a time, in the order you want them tried.

Look at a profile first if you like — this changes nothing and needs no
privileges:

```bash
steganon inspect /path/to/profile
```

Then add it. The path is either a folder holding a `.ovpn` with its
certificates, or a self-contained `.ovpn` file:

```bash
sudo steganon add /path/to/profile
```

Each one you add goes to the end of the priority order, so the first you add
is the first that will be tried. The name is guessed from the folder or the
server address; `--name` overrides it, and `--country XX` sets the two-letter
code used for the flag if the guess was wrong.

### Credentials, per location

**Every location keeps its own username and password**, beside its own
certificates:

```bash
sudo steganon credentials <name>
```

This is per location rather than per installation because providers do not
agree. Some issue a single pair for the whole account; others a different pair
for every server — and with a shared pair, failover to a second country would
fail at the moment it was needed most. Some profiles authenticate with the
certificate alone and need no pair at all; `steganon add` says which kind it
just imported.

Whatever the provider gave you, it is a **separate pair for manual setup**, not
your account password. That is the most common cause of a failed connection.
The command asks without echoing to the screen and stores the pair readable
only by the administrator. It is never passed as a command argument — anything
on a command line is visible to every user of the machine.

Removing a location deletes its credentials along with its certificates.

### Then try it

```bash
sudo steganon up
sudo steganon status
```

Once you are sure:

```bash
sudo steganon autostart on
```

## Usage

| Command | What it does |
|---|---|
| `steganon status` | what is true right now, with every check |
| `steganon inspect <path>` | read a profile without importing it |
| `steganon up` / `down` | connect / disconnect |
| `steganon down --service` | stop the service too |
| `steganon down --permanent` | and do not start on the next boot |
| `steganon add <path>` | add a location (`--name`, `--country XX`) |
| `steganon credentials <name>` | that location's username and password |
| `steganon remove <name>` | remove one, with its secrets |
| `steganon order --set a b c` | priority order |
| `steganon latency` | latency per location |
| `steganon firewall rollback` | **if something goes wrong** |

The GUI opens with `steganon-gui` or from the applications menu.

## How it works

Five layers. The first three are the security, and they work even if the GUI
never runs at all.

1. **Firewall** — outbound only through the tunnel, loopback, the local
   network, and the VPN servers' addresses. Everything else is dropped. The
   allowed addresses follow your locations: adding or removing one updates
   the running firewall too.
2. **Tunnel** (`openvpn`) — one location at a time; changing it means
   rewriting the profile.
3. **Name resolution** — the server names are resolved *before* the rules are
   applied, while there is still a network.
4. **Supervisor** — a four-level health check, with automatic failover on
   repeated failure.
5. **GUI** — runs as an ordinary user; anything needing privileges goes
   through the system's own elevation mechanism.

### Two decisions that may surprise you

**One `remote` per profile, not a list.** OpenVPN supports multiple servers
and it would be natural to hand it all of them. In practice that does not work
for switching *country*: each name resolves to dozens of addresses in the same
country, and after a drop OpenVPN keeps the last one it used. Measured with
the Greek server deliberately blocked — three consecutive attempts all landed
on Greek addresses. Changing country belongs to the supervisor.

**The identity check does not look at country.** It asks "is my outbound
address different from my real one?" and not "am I in the right country?".
Geolocation databases disagree with each other: the same address showed up as
Athens from two services and as Czechia from a third. "It is not mine" is a
fact; "it is in Greece" is an opinion.

## If something goes wrong

You are left without a network:

```bash
sudo steganon firewall rollback     # restore the previous state
sudo steganon firewall off          # remove the firewall entirely
```

The connection will not come up: the most common reason is wrong credentials —
make sure you are using the manual-setup pair and not your account password.
`sudo steganon status` shows where it stopped, and OpenVPN's own log
(`/run/steganon/openvpn.log` on Linux, `C:\ProgramData\Steganon\openvpn.log`
on Windows) shows what it said itself.

The firewall looks inactive in the GUI when it is not: the GUI reads the state
from a file the service writes. If the service is not running, run
`sudo steganon status` once.

## Two systems, one core

The code that decides — settings, health checks, location order, translations
— is shared. Only what has no equivalent between the two systems changes:

| | Linux | Windows |
|---|---|---|
| Firewall | `nftables`, a rule set replaced atomically | Windows Firewall, permanent rules with a shared prefix |
| At boot | a service loading **before** the network | the rules are already permanent; not needed |
| Supervisor | `systemd` | a scheduled task running as SYSTEM |
| GUI | GTK 4 + libadwaita | Qt |
| File protection | permission bits and owner | a clean access control list |

One substantial difference is worth calling out: **on Windows the firewall
rules survive a reboot**. On Linux a separate service is needed before the
network, purely to rebuild them — and with it comes the gap between the
network coming up and the rules being enforced. On Windows that gap does not
exist at all.

## Uninstalling

**Linux**

```bash
sudo ./uninstall.sh              # keeps settings and certificates
sudo ./uninstall.sh --purge      # deletes those too
```

**Windows** — as administrator:

```powershell
powershell -ExecutionPolicy Bypass -File uninstall.ps1
powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Purge
```

## What it does not do

- **It is not a VPN provider.** You need your own account and `.ovpn` files.
- **No WireGuard support** for now — OpenVPN only. (The provider used during
  development does not hand out WireGuard files for manual setup, only through
  its own clients.)
- **No split tunnelling.** Either everything goes through the tunnel or
  nothing does; every exception is a hole.
- **It does not hide from your ISP that you are using a VPN.**

## License

MIT. See [LICENSE](LICENSE).

---

Built for a home lab, and shared because the problem is not only mine. No
warranties: read what it does before you run it on your machine.
