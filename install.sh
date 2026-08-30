#!/usr/bin/env bash
#
# Installing Steganon.
#
# WARNING: this tool changes the network rules of the entire machine. Once it
# is on, no traffic leaves outside the tunnel — apart from the local network.
# Try it in a virtual machine first.

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Needs root: sudo ./install.sh" >&2; exit 1; }

PREFIX=/usr/local
LIBDIR=$PREFIX/lib/steganon
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "▸ Checking prerequisites"
for tool in nft openvpn python3; do
  command -v "$tool" >/dev/null || { echo "  Missing: $tool" >&2; exit 1; }
done
python3 -c 'import gi' 2>/dev/null || echo "  (without python3-gi the GUI will not run)"

echo "▸ Copying files"
install -d "$LIBDIR"
cp -r "$HERE/steganon" "$LIBDIR/"

cat > "$PREFIX/bin/steganon" <<'LAUNCH'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/local/lib/steganon")
from steganon.cli import main
sys.exit(main())
LAUNCH
chmod 755 "$PREFIX/bin/steganon"

cat > "$PREFIX/bin/steganon-gui" <<'LAUNCH'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/local/lib/steganon")
from steganon.gui import main
sys.exit(main())
LAUNCH
chmod 755 "$PREFIX/bin/steganon-gui"

echo "▸ Services and permissions"
install -m 644 "$HERE/systemd/"*.service /etc/systemd/system/
install -m 644 "$HERE/data/org.homelab.Steganon.policy" /usr/share/polkit-1/actions/
# The file has to be named after the application id, or the desktop cannot
# match the running window to its icon and falls back to a generic one.
rm -f /usr/share/applications/steganon.desktop
install -m 644 "$HERE/data/org.homelab.Steganon.desktop" /usr/share/applications/

install -d /usr/share/icons/hicolor/scalable/apps
install -d /usr/share/icons/hicolor/symbolic/apps
install -m 644 "$HERE/data/icons/steganon.svg" /usr/share/icons/hicolor/scalable/apps/
install -m 644 "$HERE/data/icons/"*-symbolic.svg /usr/share/icons/hicolor/symbolic/apps/
gtk-update-icon-cache -qtf /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database -q /usr/share/applications 2>/dev/null || true

systemctl daemon-reload

# The folder is world readable: the GUI runs as an ordinary user and needs the
# location list. The secrets are protected separately — the credentials and the
# private keys stay administrator-only.
install -d -m 755 /etc/steganon /etc/steganon/profiles

echo
echo "Done. Next steps:"
echo "  1. Add a location:      steganon add <folder-or-file.ovpn>"
echo "  2. Its credentials:     steganon credentials <name>"
echo "     (repeat 1-2 for every location you want)"
echo "  3. Try it by hand:      steganon up   ->   steganon status"
echo "  4. Make it permanent:   systemctl enable --now steganon"
echo
echo "If something goes wrong: steganon firewall rollback"
echo "Full removal:            steganon down --permanent, then ./uninstall.sh"
