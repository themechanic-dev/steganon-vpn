#!/usr/bin/env bash
#
# Removing Steganon.
#
# It stops the protection first, then removes the files. The settings and the
# certificates stay unless the opposite is asked for explicitly — an uninstall
# must not destroy data the user put there.

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Needs root: sudo ./uninstall.sh" >&2; exit 1; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "▸ Stopping protection"
systemctl disable --now steganon.service 2>/dev/null || true
systemctl disable --now steganon-firewall.service 2>/dev/null || true
/usr/local/bin/steganon down 2>/dev/null || nft flush ruleset 2>/dev/null || true

echo "▸ Removing files"
rm -f  /usr/local/bin/steganon /usr/local/bin/steganon-gui
rm -rf /usr/local/lib/steganon
rm -f  /etc/systemd/system/steganon.service /etc/systemd/system/steganon-firewall.service
rm -f  /usr/share/polkit-1/actions/org.homelab.Steganon.policy
rm -f  /usr/share/applications/steganon.desktop
rm -f  /usr/share/icons/hicolor/scalable/apps/steganon.svg
rm -f  /usr/share/icons/hicolor/symbolic/apps/steganon-*-symbolic.svg \
       /usr/share/icons/hicolor/symbolic/apps/steganon-symbolic.svg
rm -rf /run/steganon
systemctl daemon-reload
gtk-update-icon-cache -qtf /usr/share/icons/hicolor 2>/dev/null || true

if [ $PURGE -eq 1 ]; then
  echo "▸ Deleting settings and certificates"
  rm -rf /etc/steganon
else
  echo "▸ The settings stay in /etc/steganon (--purge to remove them)"
fi

echo
echo "Removed. Traffic now leaves unprotected."
