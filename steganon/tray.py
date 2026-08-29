"""System tray icon.

Implements the StatusNotifierItem protocol directly over D-Bus, with no
library. The reason is practical: the ready-made indicator libraries exist
only for GTK 3, while the application is GTK 4 — and the two versions cannot
coexist in one process. The protocol, on the other hand, is a handful of
properties and one method, so implementing it directly is cheaper than a
second process that would have to stay in sync.

The icon shows its state through its shape, not only through colour, so it
reads on a monochrome bar too.

Text with the country name sits beside it. The protocol also provides a
tooltip shown on hover, but GNOME never displays it: the ToolTip property is
declared in its interface and read nowhere in its code. The label beside the
icon does get through, and has the advantage of being visible all the time
rather than only on hover. The tooltip stays declared for environments that
respect it.
"""

from __future__ import annotations

from gi.repository import Gio, GLib

from .i18n import _

WATCHER = "org.kde.StatusNotifierWatcher"
WATCHER_PATH = "/StatusNotifierWatcher"
ITEM_PATH = "/StatusNotifierItem"

# A shield, not a network symbol: the question the icon answers is not "is
# there a connection" but "am I covered". The three levels exist in every
# modern theme and differ in shape — full shield, shield with a mark, shield
# with a warning — so they are distinguishable without colour too.
ICON_ON = "steganon-symbolic"
ICON_WARN = "steganon-partial-symbolic"
ICON_OFF = "steganon-open-symbolic"

# If ours have not been installed (e.g. running from the project folder), we
# fall back to the theme's icons rather than leaving a gap in the bar.
FALLBACK = {
    ICON_ON: "security-high-symbolic",
    ICON_WARN: "security-medium-symbolic",
    ICON_OFF: "security-low-symbolic",
}


def _resolve(name: str) -> str:
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gdk, Gtk
        display = Gdk.Display.get_default()
        if display is None:
            return name
        theme = Gtk.IconTheme.get_for_display(display)
        return name if theme.has_icon(name) else FALLBACK.get(name, name)
    except Exception:
        return name

INTROSPECTION = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="XAyatanaLabel" type="s" access="read"/>
    <property name="XAyatanaLabelGuide" type="s" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <method name="Activate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="ContextMenu">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Scroll">
      <arg name="delta" type="i" direction="in"/>
      <arg name="orientation" type="s" direction="in"/>
    </method>
    <signal name="NewIcon"/>
    <signal name="NewStatus"><arg name="status" type="s"/></signal>
    <signal name="NewToolTip"/>
  </interface>
</node>
"""


class TrayIcon:
    """The icon. If the environment does not support it, it does nothing."""

    def __init__(self, on_activate, app_id: str = "steganon") -> None:
        self.on_activate = on_activate
        self.app_id = app_id
        self.icon = _resolve(ICON_OFF)
        self.tooltip = _("Steganon")
        self.label = ""
        self.available = False
        self._conn: Gio.DBusConnection | None = None
        self._reg_id = 0
        self._own_id = 0
        self._bus_name = ""

        try:
            self._start()
        except GLib.Error:
            # With no bar that accepts icons, the application works normally —
            # just without the shortcut.
            self.available = False

    # ── setup ─────────────────────────────────────────────────────────────

    def _start(self) -> None:
        self._conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
        self._reg_id = self._conn.register_object(
            ITEM_PATH, node.interfaces[0],
            self._on_method, self._on_get_property, None,
        )

        # The name has to be unique per process: the watcher keys its index
        # on it.
        import os
        self._bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self._own_id = Gio.bus_own_name_on_connection(
            self._conn, self._bus_name,
            Gio.BusNameOwnerFlags.NONE,
            lambda *_a: self._register_with_watcher(),
            None,
        )

    def _register_with_watcher(self) -> None:
        try:
            self._conn.call_sync(
                WATCHER, WATCHER_PATH, WATCHER, "RegisterStatusNotifierItem",
                GLib.Variant("(s)", (self._bus_name,)),
                None, Gio.DBusCallFlags.NONE, 3000, None,
            )
            self.available = True
        except GLib.Error:
            self.available = False

    # ── answers to the bar ────────────────────────────────────────────────

    def _on_get_property(self, _conn, _sender, _path, _iface, name):
        values = {
            "Category": GLib.Variant("s", "SystemServices"),
            "Id": GLib.Variant("s", self.app_id),
            "Title": GLib.Variant("s", _("Steganon")),
            "Status": GLib.Variant("s", "Active"),
            "IconName": GLib.Variant("s", self.icon),
            "AttentionIconName": GLib.Variant("s", ICON_WARN),
            "OverlayIconName": GLib.Variant("s", ""),
            "Menu": GLib.Variant("o", "/NO_DBUSMENU"),
            # false = a left click sends "Activate" instead of opening a menu.
            # That is what we want: one click brings the window forward.
            "ItemIsMenu": GLib.Variant("b", False),
            "ToolTip": GLib.Variant("(sa(iiay)ss)",
                                    (self.icon, [], _("Steganon"), self.tooltip)),
            "XAyatanaLabel": GLib.Variant("s", self.label),
            # The "guide" text reserves width so the bar does not jump every
            # time the country changes.
            "XAyatanaLabelGuide": GLib.Variant("s", "🇬🇷 Netherlands"),
        }
        return values.get(name)

    def _on_method(self, _conn, _sender, _path, _iface, method, _params, invocation):
        if method in ("Activate", "SecondaryActivate", "ContextMenu"):
            self.on_activate()
        invocation.return_value(None)

    # ── status updates ────────────────────────────────────────────────────

    def update(self, healthy: bool, foreign: bool, detail: str = "",
               label: str = "") -> None:
        icon = _resolve(ICON_ON if healthy else (ICON_WARN if foreign else ICON_OFF))
        tooltip = detail or _("Protected" if healthy else "Exposed")
        changed = (icon, tooltip, label) != (self.icon, self.tooltip, self.label)
        self.icon, self.tooltip, self.label = icon, tooltip, label
        if not (changed and self.available and self._conn):
            return

        for signal in ("NewIcon", "NewToolTip"):
            try:
                self._conn.emit_signal(
                    None, ITEM_PATH, "org.kde.StatusNotifierItem", signal, None
                )
            except GLib.Error:
                pass

        # The label has no signal of its own in the standard; it travels with
        # the ordinary property-changed message, which is what the GNOME
        # extension watches.
        try:
            self._conn.emit_signal(
                None, ITEM_PATH, "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                GLib.Variant("(sa{sv}as)", (
                    "org.kde.StatusNotifierItem",
                    {"XAyatanaLabel": GLib.Variant("s", self.label)},
                    [],
                )),
            )
        except GLib.Error:
            pass

    def dispose(self) -> None:
        if self._own_id:
            Gio.bus_unown_name(self._own_id)
        if self._reg_id and self._conn:
            self._conn.unregister_object(self._reg_id)
