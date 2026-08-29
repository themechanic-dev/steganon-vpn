"""The graphical interface.

Runs as an ordinary user. Anything needing privileges goes through `pkexec`,
so there is never a graphical application with administrator rights on screen.

State is read from the same files the supervisor writes, so the window shows
the truth even when it was opened after the connection came up.
"""

from __future__ import annotations

import subprocess
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Gio, Pango  # noqa: E402

from . import firewall, monitor, tunnel  # noqa: E402
from . import prefs  # noqa: E402
from .tray import TrayIcon  # noqa: E402
from .config import Settings, autostart_active  # noqa: E402
from .i18n import LANGUAGES, _, detect, get_language, set_language  # noqa: E402

APP_ID = "org.homelab.Steganon"

# How many locations the window grows for on its own. Beyond that, the list
# scrolls instead of pushing the settings off screen.
FIT_LOCATIONS = 10
HEADER_HEIGHT = 46

# Flags come from each location's own country code, worked out arithmetically
# from the two letters. There is deliberately no table of countries here: one
# would decide which places the program considers normal, and every provider
# offers somewhere it would not list.

STYLE = """
.hero {
  border-radius: 18px;
  padding: 26px 22px;
  border: 1px solid alpha(currentColor, .10);
}
.hero.on      { background: linear-gradient(150deg, alpha(@success_color,.20), alpha(@success_color,.06)); }
.hero.off     { background: linear-gradient(150deg, alpha(@error_color,.20),   alpha(@error_color,.06)); }
.hero.working { background: linear-gradient(150deg, alpha(@warning_color,.20), alpha(@warning_color,.06)); }

.hero-title  { font-size: 25px; font-weight: 800; letter-spacing: -.4px; }
.hero-detail { font-size: 13px; opacity: .72; }

.dot { min-width: 13px; min-height: 13px; border-radius: 999px; }
.dot.on      { background: @success_color; box-shadow: 0 0 0 5px alpha(@success_color,.20); }
.dot.off     { background: @error_color;   box-shadow: 0 0 0 5px alpha(@error_color,.20); }
.dot.working { background: @warning_color; box-shadow: 0 0 0 5px alpha(@warning_color,.20); }

.metric-value { font-size: 16px; font-weight: 700; font-feature-settings: "tnum"; }
.flag { font-size: 19px; }

/* A solid red button on a green background came out muddy. A neutral
   surface with a red outline reads clearly in both themes. */
button.leave {
  background: alpha(currentColor, .06);
  border: 1.5px solid alpha(@error_color, .55);
  color: @error_color;
  font-weight: 700;
}
button.leave:hover { background: alpha(@error_color, .13); }
.metric-label { font-size: 11px; opacity: .62; letter-spacing: .6px; }
.rank { font-feature-settings: "tnum"; opacity: .45; font-weight: 700; min-width: 22px; }
.mono { font-family: monospace; font-size: 12px; }
"""


def _run_privileged(*args: str) -> tuple[bool, str]:
    """Runs a Steganon command with privileges, through the system dialog."""
    exe = sys.argv[0] if sys.argv[0].endswith("steganon") else "steganon"
    proc = subprocess.run(
        ["pkexec", exe, *args], capture_output=True, text=True
    )
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


def _run_privileged_input(*args: str, text: str) -> tuple[bool, str]:
    """Like _run_privileged, but passes data on standard input.

    Anything on a command line is visible to every user of the machine through
    the process list. Passwords never go through there.
    """
    exe = sys.argv[0] if sys.argv[0].endswith("steganon") else "steganon"
    proc = subprocess.run(["pkexec", exe, *args], input=text,
                          capture_output=True, text=True)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


class Window(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app)
        self.prefs = prefs.load()
        self.set_default_size(int(self.prefs["window_width"]),
                              int(self.prefs["window_height"] or 0) or 700)
        self._sized = False
        self.settings = Settings.load()
        set_language(self.prefs["language"] or self.settings.language or detect())
        self.busy = False

        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toasts.set_child(root)

        header = Adw.HeaderBar()
        header.add_css_class("flat")
        menu = Gio.Menu()
        button = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header.pack_end(button)
        root.append(header)

        self.scroller = Gtk.ScrolledWindow(vexpand=True)
        self.scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        root.append(self.scroller)
        self.menu = menu

        # The icon is set up BEFORE the first build: "_build_page" ends with a
        # status check, and if the icon does not exist yet it stays in its
        # initial "disconnected" look until the next cycle — showing danger
        # where there is none.
        # If the environment does not support it, the application works fine.
        self.tray = TrayIcon(self._on_tray_click)

        self._install_actions()
        self._build_page()
        self.connect("close-request", self._on_close)
        GLib.timeout_add_seconds(6, self._tick)

    def _on_tray_click(self) -> None:
        """Clicking the icon: brings the window forward, or hides it."""
        if self.get_visible():
            self.set_visible(False)
        else:
            self.present()

    def _on_close(self, *_args) -> bool:
        """Closing hides the window, it does not destroy it.

        That keeps its position on the desktop. Under Wayland an application
        cannot ask where it will appear — if the window were destroyed and
        rebuilt, the window manager would place it from scratch, usually in
        the centre. By keeping the same window alive and merely hidden, it
        comes back where the user left it.


        When there is no tray icon, closing means quitting: otherwise the
        application would vanish with no way to bring it back.
        """
        width, height = self.get_default_size()
        if width > 0 and height > 0:
            prefs.save(window_width=width, window_height=height)

        if getattr(self, "tray", None) and self.tray.available:
            self.set_visible(False)
            return True     # stops the close
        return False

    def _build_page(self) -> None:
        """Builds the content. Called again when the language changes."""
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(6)
        for side in ("start", "end", "bottom"):
            getattr(page, f"set_margin_{side}")(18)

        self._rows = []
        page.append(self._build_hero())
        page.append(self._build_metrics())
        page.append(self._build_locations())
        page.append(self._build_options())
        self.scroller.set_child(page)

        # The title follows the language too: it appears on the window, in the
        # taskbar and in the window switcher, so a Greek word in an English
        # environment shows up everywhere.
        self.set_title(_("Steganon"))

        self.menu.remove_all()
        self.menu.append(_("Measure latency"), "win.latency")
        self.menu.append(_("Refresh"), "win.refresh")
        self.menu.append(_("Quit"), "win.quit")
        self.menu.append(_("Shut down protection…"), "win.shutdown")
        self.refresh()
        GLib.idle_add(self._fit_to_content)

    def _fit_to_content(self) -> bool:
        """Opens at a size that fits everything, with no hidden settings.

        The height is not fixed — it grows with each location — so it is
        measured rather than written as a number. Two limits hold it back: it
        does not grow past FIT_LOCATIONS locations, and never past three
        quarters of the screen. Scrolling takes care of the rest.
        """
        if self._sized or self.prefs.get("window_height"):
            return False

        page = self.scroller.get_child()
        if page is None:
            return False
        width = int(self.prefs["window_width"])
        needed = page.measure(Gtk.Orientation.VERTICAL, width)[1] + HEADER_HEIGHT

        # Past the first few locations the extra height does not count: the
        # window would get disproportionately tall for something that scrolls
        surplus = len(self.settings.locations) - FIT_LOCATIONS
        if surplus > 0 and self._rows:
            row_height = self._rows[0].get_allocated_height() or 47
            needed -= surplus * row_height

        limit = 900
        surface = self.get_surface()
        monitor = self.get_display().get_monitor_at_surface(surface) if surface else None
        if monitor is not None:
            limit = int(monitor.get_geometry().height * 0.75)

        self.set_default_size(width, max(520, min(needed, limit)))
        self._sized = True
        return False

    # ── state ─────────────────────────────────────────────────────────────

    def _build_hero(self) -> Gtk.Widget:
        self.hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.hero.add_css_class("hero")

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.dot = Gtk.Box()
        self.dot.add_css_class("dot")
        self.dot.set_valign(Gtk.Align.CENTER)
        row.append(self.dot)

        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        self.title = Gtk.Label(xalign=0, label=_("Checking…"))
        self.title.add_css_class("hero-title")
        self.detail = Gtk.Label(xalign=0, label="")
        self.detail.add_css_class("hero-detail")
        self.detail.set_wrap(True)
        self.detail.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        titles.append(self.title)
        titles.append(self.detail)
        row.append(titles)
        self.hero.append(row)

        self.action = Gtk.Button(label=_("Connect"))
        self.action.add_css_class("pill")
        self.action.add_css_class("suggested-action")
        self.action.set_size_request(-1, 42)
        self.action.connect("clicked", self._on_action)
        self.hero.append(self.action)

        return self.hero

    def _build_metrics(self) -> Gtk.Widget:
        grid = Gtk.Grid(column_spacing=10, row_spacing=10, column_homogeneous=True)
        self.metrics: dict[str, Gtk.Label] = {}
        cells = [
            ("ip", _("ADDRESS"), 0, 0), ("server", _("SERVER"), 1, 0),
            ("latency", _("LATENCY"), 0, 1), ("firewall", _("FIREWALL"), 1, 1),
        ]
        for key, label, col, rowi in cells:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            card.add_css_class("card")
            card.set_margin_top(2)
            for side in ("top", "bottom", "start", "end"):
                getattr(card, f"set_margin_{side}")(0)
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            inner.set_margin_top(13); inner.set_margin_bottom(13)
            inner.set_margin_start(14); inner.set_margin_end(14)
            cap = Gtk.Label(xalign=0, label=label)
            cap.add_css_class("metric-label")
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
            val = Gtk.Label(xalign=0, label="—")
            val.add_css_class("metric-value")
            val.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            if key == "server":
                self.server_flag = Gtk.Label(label="")
                self.server_flag.add_css_class("flag")
                line.append(self.server_flag)
            line.append(val)
            inner.append(cap); inner.append(line)
            card.append(inner)
            grid.attach(card, col, rowi, 1, 1)
            self.metrics[key] = val
        return grid

    # ── locations ─────────────────────────────────────────────────────────

    def _build_locations(self) -> Gtk.Widget:
        self.loc_group = Adw.PreferencesGroup(
            title=_("Priority order"),
            description=_("Top to bottom. If a location does not respond, the next one is tried."),
        )
        add = Gtk.Button(icon_name="list-add-symbolic", valign=Gtk.Align.CENTER)
        add.add_css_class("flat")
        add.set_tooltip_text(_("Add location"))
        add.connect("clicked", self._on_add)
        self.loc_group.set_header_suffix(add)

        self._fill_locations()
        return self.loc_group

    def _fill_locations(self) -> None:
        for row in getattr(self, "_rows", []):
            self.loc_group.remove(row)
        self._rows = []

        for index, loc in enumerate(self.settings.locations):
            # A location that will fail for want of a password says so here,
            # rather than at the moment failover reaches it.
            missing = loc.needs_auth and not loc.has_credentials
            subtitle = loc.remote if not missing else \
                f"{loc.remote}  ·  {_('No credentials yet')}"
            row = Adw.ActionRow(title=loc.label, subtitle=subtitle)
            prefix = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            rank = Gtk.Label(label=str(index + 1))
            rank.add_css_class("rank")
            emblem = Gtk.Label(label=loc.flag)
            emblem.add_css_class("flag")
            prefix.append(rank); prefix.append(emblem)
            row.add_prefix(prefix)

            # The credentials belong to this location, so the way to set them
            # is on this row — not in a menu that would have to ask which one.
            key = Gtk.Button(icon_name="dialog-password-symbolic",
                             valign=Gtk.Align.CENTER,
                             tooltip_text=_("Set credentials"))
            key.add_css_class("flat")
            if missing:
                key.add_css_class("suggested-action")
            key.connect("clicked", self._on_credentials, loc.name)
            row.add_suffix(key)

            switch = Gtk.Switch(active=loc.enabled, valign=Gtk.Align.CENTER)
            switch.connect("state-set", self._on_toggle, loc.name)
            row.add_suffix(switch)

            up = Gtk.Button(icon_name="go-up-symbolic", valign=Gtk.Align.CENTER)
            up.add_css_class("flat")
            up.set_sensitive(index > 0)
            up.connect("clicked", self._on_move, loc.name, -1)
            row.add_suffix(up)

            down = Gtk.Button(icon_name="go-down-symbolic", valign=Gtk.Align.CENTER)
            down.add_css_class("flat")
            down.set_sensitive(index < len(self.settings.locations) - 1)
            down.connect("clicked", self._on_move, loc.name, +1)
            row.add_suffix(down)

            drop = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
            drop.add_css_class("flat")
            drop.set_tooltip_text(_("Remove"))
            # The last location is not removable: with none left, the tool has
            # nowhere to connect.
            drop.set_sensitive(len(self.settings.locations) > 1)
            drop.connect("clicked", self._on_remove, loc.name, loc.label)
            row.add_suffix(drop)

            self.loc_group.add(row)
            self._rows.append(row)

    def _build_options(self) -> Gtk.Widget:
        group = Adw.PreferencesGroup(title=_("Settings"))

        self.ipv6_row = Adw.SwitchRow(
            title=_("Block IPv6"),
            subtitle=_("The provider's tunnel carries IPv4 only; without blocking, IPv6 traffic bypasses it."),
            active=self.settings.block_ipv6,
        )
        self.ipv6_row.connect("notify::active", self._on_option, "block_ipv6")
        group.add(self.ipv6_row)

        self.autostart_row = Adw.SwitchRow(
            title=_("Connect at startup"),
            subtitle=_("The firewall loads before the network on every boot, and the icon appears in the tray."),
            active=autostart_active(),
        )
        self.autostart_row.connect("notify::active", self._on_autostart)
        group.add(self.autostart_row)

        codes = list(LANGUAGES)
        names = Gtk.StringList.new([LANGUAGES[c] for c in codes])
        self.lang_row = Adw.ComboRow(title=_("Language"), model=names)
        self.lang_row.set_selected(codes.index(get_language()))
        self.lang_row.connect("notify::selected", self._on_language, codes)
        group.add(self.lang_row)
        return group

    def _on_language(self, row: Adw.ComboRow, _param, codes: list[str]) -> None:
        code = codes[row.get_selected()]
        if code == get_language():
            return
        set_language(code)
        # Written to the user's folder, not to /etc: the language is a display
        # preference and must not ask for a password. When it went through
        # pkexec, the window froze waiting for the dialog and the page was
        # left half translated.
        prefs.save(language=code)
        self._build_page()

    # ── actions ───────────────────────────────────────────────────────────

    def _install_actions(self) -> None:
        for name, handler in (("latency", self._on_latency),
                              ("refresh", lambda *_: self.refresh()),
                              ("quit", self._on_quit),
                              ("shutdown", self._on_shutdown)):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

    def _on_action(self, _button: Gtk.Button) -> None:
        # We only disconnect what we control. If something else set the tunnel
        # up, the button means "take control", not "close somebody else's".
        connected = monitor.check(self.settings).healthy
        self._set_busy(_("Disconnecting…") if connected else _("Connecting…"))

        def work() -> bool:
            ok, output = _run_privileged("down" if connected else "up")
            self.busy = False
            self._toast(_("Disconnected.") if connected and ok else
                        (_("Connected.") if ok else (output.splitlines() or [_("Failed")])[-1]))
            self.refresh()
            return False

        GLib.timeout_add(120, work)

    def _on_quit(self, *_args) -> None:
        """Closes the window — not the connection.

        The distinction is not obvious to somebody looking at a VPN window, so
        it is said outright rather than implied.
        """
        connected = monitor.check(self.settings).healthy
        if not connected:
            self.get_application().quit()
            return

        dialog = Adw.AlertDialog(
            heading=_("Quit the application?"),
            body=_("The connection and firewall stay active. This window is only the front end — protection runs as a system service.\n\nTo actually stop protection, press “Disconnect” first."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("quit", _("Quit"))
        dialog.set_default_response("cancel")
        dialog.connect("response", lambda _d, r: r == "quit" and self.get_application().quit())
        dialog.present(self)

    def _on_shutdown(self, *_args) -> None:
        """Closes everything: connection, firewall, service and window.

        The warning is not decorative. After this the machine reaches the
        internet with no protection at all, and the difference from a plain
        "Quit" is not visible anywhere else.
        """
        dialog = Adw.AlertDialog(
            heading=_("Shut down protection?"),
            body=_("The connection, firewall and service will all stop. The machine will reach the internet **with no protection**, with your real address visible."),
        )
        keep = Adw.SwitchRow(
            title=_("Do not start on next boot either"),
            active=False,
        )
        group = Adw.PreferencesGroup()
        group.add(keep)
        group.set_margin_top(8)
        dialog.set_extra_child(group)

        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("shutdown", _("Shut down"))
        dialog.set_response_appearance("shutdown", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.connect("response", self._on_shutdown_confirmed, keep)
        dialog.present(self)

    def _on_shutdown_confirmed(self, _d, response: str, keep: Adw.SwitchRow) -> None:
        if response != "shutdown":
            return
        self._set_busy(_("Disconnecting…"))

        def work() -> bool:
            # The command does, in order: stop the service, disconnect
            # cleanly, remove the firewall. The firewall goes last so there
            # is never a moment with an open network and no protection.
            args = ["down", "--service"]
            if keep.get_active():
                args.append("--permanent")
            ok, output = _run_privileged(*args)
            self.busy = False
            if ok:
                self.get_application().quit()
            else:
                self._toast((output.splitlines() or [_("Failed")])[-1].strip())
                self.refresh()
            return False

        GLib.timeout_add(120, work)

    # ── credentials ───────────────────────────────────────────────────────

    def _on_credentials(self, _button, name: str) -> None:
        """Asks for one location's username and password.

        Per location, because providers disagree: some issue a single pair for
        the account, others a different one per server. Asking on the row
        removes the question of which location it applies to.

        It is not the account password either — providers issue a separate
        pair for manual setup, and that is the most common cause of a failed
        connection.
        """
        location = self.settings.find(name)
        if location is None:
            return
        dialog = Adw.AlertDialog(
            heading=_("Credentials for {name}", name=location.label),
            body=_("The pair your provider issues for manual setup — not your account password.")
                 + "\n\n"
                 + _("Each location has its own username and password. Some providers issue one pair for the whole account, others a different pair per server."),
        )
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(8)

        user_row = Adw.EntryRow(title=_("Username"))
        pass_row = Adw.PasswordEntryRow(title=_("Password"))
        group = Adw.PreferencesGroup()
        group.add(user_row)
        group.add(pass_row)
        box.append(group)
        dialog.set_extra_child(box)

        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("save", _("Save"))
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.connect("response", self._on_credentials_done, user_row, pass_row, name)
        dialog.present(self)

    def _on_credentials_done(self, _d, response: str, user_row, pass_row,
                             name: str) -> None:
        if response != "save":
            return
        username = user_row.get_text().strip()
        password = pass_row.get_text()
        if not username or not password:
            self._toast(_("Both fields are required."))
            return
        # They are passed to the privileged command on standard input, so they
        # never appear in the process list.
        ok, output = _run_privileged_input("credentials", name, "--stdin",
                                           text=f"{username}\n{password}\n")
        if ok:
            # Re-read from disk so the row loses its "no credentials" note.
            self.settings = Settings.load()
            self._fill_locations()
            self._toast(_("Saved."))
        else:
            self._toast((output.splitlines() or [_("Failed")])[-1].strip())

    def _on_add(self, _b: Gtk.Button) -> None:
        chooser = Gtk.FileDialog(title=_("Choose a .ovpn file"))
        filters = Gio.ListStore.new(Gtk.FileFilter)
        ovpn = Gtk.FileFilter(name="OpenVPN (*.ovpn)")
        ovpn.add_pattern("*.ovpn")
        filters.append(ovpn)
        chooser.set_filters(filters)
        chooser.open(self, None, self._on_add_chosen)

    def _on_add_chosen(self, dialog: Gtk.FileDialog, result) -> None:
        try:
            gfile = dialog.open_finish(result)
        except GLib.Error:
            return          # the user cancelled
        if gfile is None:
            return
        path = gfile.get_path()
        ok, output = _run_privileged("add", path)
        if ok:
            self.settings = Settings.load()
            self._build_page()
            self._toast(_("Location added."))
        else:
            self._toast((output.splitlines() or [_("Failed")])[-1].strip())

    def _on_remove(self, _b: Gtk.Button, name: str, label: str) -> None:
        dialog = Adw.AlertDialog(
            heading=_("Remove “{name}”?", name=label),
            body=_("The location's certificates will be deleted."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("remove", _("Remove"))
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.connect("response", self._on_remove_confirmed, name)
        dialog.present(self)

    def _on_remove_confirmed(self, _d, response: str, name: str) -> None:
        if response != "remove":
            return
        ok, output = _run_privileged("remove", name)
        if ok:
            self.settings = Settings.load()
            self._build_page()
            self._toast(_("Location removed."))
        else:
            self._toast((output.splitlines() or [_("Failed")])[-1].strip())

    def _on_move(self, _b: Gtk.Button, name: str, delta: int) -> None:
        if self.settings.move(name, delta):
            self._save_order()
            self._fill_locations()

    def _on_toggle(self, _s: Gtk.Switch, state: bool, name: str) -> bool:
        for loc in self.settings.locations:
            if loc.name == name:
                loc.enabled = state
        self._save_order()
        return False

    def _on_autostart(self, row: Adw.SwitchRow, _p) -> None:
        """One switch, two destinations.

        The protection is configured on the system and needs privileges; the
        window in the user's session and does not. They happen together
        because to the user it is one decision.
        """
        enabled = row.get_active()
        self.settings.autostart = enabled
        prefs.set_autostart(enabled)
        ok, output = _run_privileged("autostart", "on" if enabled else "off")
        if not ok:
            self._toast((output.splitlines() or [_("The change was not saved.")])[-1].strip())

    def _on_option(self, row: Adw.SwitchRow, _p, field: str) -> None:
        setattr(self.settings, field, row.get_active())
        self._save_order()
        # A setting that shapes the rules has to reach the rules. Saved but
        # not applied, the switch would report protection that is not there.
        if firewall.is_active():
            _run_privileged("firewall", "reapply")
            self.refresh()

    def _save_order(self) -> None:
        order = [loc.name for loc in self.settings.locations]
        args = ["order", "--set", *order]
        ok, _ = _run_privileged(*args)
        if not ok:
            self._toast(_("The change was not saved."))

    def _on_latency(self, *_args) -> None:
        self._toast(_("Measuring…"))

        def work() -> bool:
            results = monitor.rank_locations(self.settings)
            best = min((r for r in results if r[1]), key=lambda r: r[1], default=None)
            if best:
                self._toast(_("Fastest: {name} ({ms:.0f} ms)", name=best[0], ms=best[1]))
            else:
                self._toast(_("No location responded."))
            return False

        GLib.timeout_add(80, work)

    # ── refresh ───────────────────────────────────────────────────────────

    def _set_busy(self, message: str) -> None:
        self.busy = True
        self._style("working")
        self.title.set_text(message)
        self.detail.set_text("")
        self.action.set_sensitive(False)

    def _style(self, state: str) -> None:
        for widget in (self.hero, self.dot):
            for name in ("on", "off", "working"):
                widget.remove_css_class(name)
            widget.add_css_class(state)

    def _tick(self) -> bool:
        if not self.busy:
            self.refresh()
        return True

    def refresh(self) -> None:
        if self.busy:
            return
        health = monitor.check(self.settings)
        active = firewall.is_active()

        if health.healthy:
            self._style("on")
            self.title.set_text(_("Protected"))
            self.detail.set_text(_("All traffic goes through the tunnel."))
            self.action.set_label(_("Disconnect"))
        elif health.foreign_tunnel:
            # There is a VPN, but not ours. We do not call it "protected":
            # without our rules nobody guarantees what happens if it drops,
            # nor what IPv6 traffic does.
            self._style("working")
            self.title.set_text(_("Another connection"))
            self.detail.set_text(
                "A VPN is up, but Steganon does not control it. Without the firewall there is no guarantee if it drops."
            )
            self.action.set_label(_("Take control"))
        else:
            self._style("off")
            self.title.set_text(_("Exposed"))
            self.detail.set_text(_(health.detail) if health.detail else _("Traffic is not going through a tunnel."))
            self.action.set_label(_("Connect"))

        connected = health.healthy
        for name in ("destructive-action", "suggested-action", "leave"):
            self.action.remove_css_class(name)
        self.action.add_css_class("leave" if connected else "suggested-action")
        self.action.set_sensitive(True)
        # Needed both by the tray and by the server card below, so it is
        # worked out before the branch rather than inside it.
        current = next(iter(self.settings.enabled_locations()), None)
        if getattr(self, "tray", None):
            where = f"{current.flag} {current.label}" if current else ""
            state = _("Protected") if health.healthy else (
                _("Another connection") if health.foreign_tunnel else _("Exposed"))
            self.tray.update(
                health.healthy, health.foreign_tunnel,
                detail=f"{state} — {where}" if health.healthy and where else state,
                label=where if health.healthy else "",
            )
        self.metrics["ip"].set_text(health.external_ip or "—")
        server = tunnel.current_server() or "—"
        short = server.split(".")[0] if server != "—" else "—"
        self.metrics["server"].set_text(short)
        self.server_flag.set_text(
            current.flag if (health.healthy and current) else "")
        self.metrics["latency"].set_text(
            f"{health.latency_ms:.0f} ms" if health.latency_ms else "—"
        )
        self.metrics["firewall"].set_text(_("on") if active else _("off"))

    def _toast(self, message: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=message, timeout=4))


class Application(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_activate(self) -> None:
        hidden = "--hidden" in sys.argv
        provider = Gtk.CssProvider()
        provider.load_from_data(STYLE.encode('utf-8'))
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        window = self.props.active_window or Window(self)
        if not hidden:
            window.present()
            return

        # With "--hidden" the application starts with no window: there is only
        # the tray icon, and the window comes with one click.
        #
        # Registering the icon is asynchronous — at this moment the tray has
        # not answered yet. Asking now whether it is available would always
        # give "no", and the window would appear on every start. We wait a
        # little and check then: if there really is no tray, the window has to
        # show, or the application would run invisible and unreachable.

        window.set_visible(False)

        def show_if_no_tray() -> bool:
            if not window.tray.available:
                window.present()
            return False

        GLib.timeout_add_seconds(4, show_if_no_tray)


def main() -> int:
    # "--hidden" is ours and GTK would reject it as unknown. We read it from
    # sys.argv in do_activate and hide it from there.
    argv = [a for a in sys.argv if a != "--hidden"]
    return Application().run(argv)


if __name__ == "__main__":
    sys.exit(main())
