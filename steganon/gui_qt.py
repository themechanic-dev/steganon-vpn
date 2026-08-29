"""The graphical interface for Windows.

Same behaviour and same look as the Linux version, in a different toolkit:
GTK does exist for Windows, but shipping it means carrying the whole GNOME
stack along. Qt installs with a single command.

The core is shared — settings, checks, translations, locations. All that
changes is how the same things are drawn.
"""

from __future__ import annotations

import subprocess
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox,
    QPushButton, QScrollArea, QSystemTrayIcon, QToolButton, QVBoxLayout, QWidget,
)

from . import firewall, monitor, prefs, tunnel
from .config import Settings, pretty
from .i18n import LANGUAGES, _, detect, get_language, set_language

FIT_LOCATIONS = 10

# Flags come from each location's own country code, worked out arithmetically
# from the two letters — the same as the Linux version. No table of countries
# lives here: one would decide which places the program considers normal.


# The colours follow the same logic as the Linux version: state shows in the
# background, and the disconnect button is neutral with a red outline rather
# than filled — it reads more clearly on a coloured surface.

STYLE = """
QWidget          { background: #1b1f22; color: #e6ecea; font-size: 13px; }
QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; }

#hero            { border-radius: 14px; padding: 18px; }
#hero[state="on"]      { background: #16302b; border: 1px solid #2e7d4f; }
#hero[state="off"]     { background: #331d1a; border: 1px solid #b03a2e; }
#hero[state="working"] { background: #2e2413; border: 1px solid #a9701a; }

#heroTitle       { font-size: 22px; font-weight: 700; }
#heroDetail      { color: #9fb0ab; font-size: 12px; }

#dot             { border-radius: 7px; min-width: 14px; max-width: 14px;
                   min-height: 14px; max-height: 14px; }
#dot[state="on"]      { background: #2ec27e; }
#dot[state="off"]     { background: #e01b24; }
#dot[state="working"] { background: #e5a50a; }

#action          { border-radius: 8px; padding: 10px; font-weight: 700; font-size: 14px; }
#action[mode="connect"]    { background: #0e6e6b; border: none; color: #ffffff; }
#action[mode="connect"]:hover { background: #12817d; }
#action[mode="leave"]      { background: rgba(255,255,255,.05);
                             border: 1px solid rgba(224,27,36,.55); color: #e08578; }
#action[mode="leave"]:hover { background: rgba(224,27,36,.13); }

#card            { background: #232a2d; border-radius: 10px; padding: 12px; }
#cardLabel       { color: #8b9a96; font-size: 10px; letter-spacing: 1px; }
#cardValue       { font-size: 15px; font-weight: 700; }

#row             { background: #232a2d; border-radius: 8px; padding: 8px; }
#rank            { color: #6f7d79; font-weight: 700; }
#rowTitle        { font-weight: 600; }
#rowSub          { color: #8b9a96; font-size: 11px; }
#groupTitle      { font-weight: 700; font-size: 14px; margin-top: 6px; }
#groupHint       { color: #8b9a96; font-size: 11px; }

QPushButton, QToolButton { background: #2b3336; border: none; border-radius: 6px; padding: 6px; }
QPushButton:hover, QToolButton:hover { background: #354044; }
QPushButton:disabled { color: #55605d; }
QComboBox        { background: #2b3336; border-radius: 6px; padding: 5px 8px; }
QLineEdit        { background: #2b3336; border: 1px solid #3a4448; border-radius: 6px; padding: 6px; }
QCheckBox        { spacing: 8px; }
"""


def _run_privileged(*args: str, text: str | None = None) -> tuple[bool, str]:
    """Runs a command with administrator rights.

    Windows has no equivalent of "pkexec" that returns output: elevation opens
    a new process. The tool is installed so that it already runs elevated when
    it needs to, and here it is simply invoked.
    """
    from .backends import windows_service as service
    launcher = service.ROOT / "steganon.cmd"
    command = [str(launcher)] if launcher.exists() else [sys.executable, "-m", "steganon.cli"]
    try:
        proc = subprocess.run(
            command + list(args), input=text, capture_output=True, text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
    except OSError as exc:
        return False, str(exc)


def _tray_pixmap(state: str) -> QIcon:
    """The tray icon, drawn at whatever size is needed.

    It is not loaded from a file: Windows has no icon theme to provide one,
    and an embedded shape works at any resolution.
    """
    size = 32
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    colours = {"on": "#2ec27e", "working": "#e5a50a", "off": "#e01b24"}
    painter.setBrush(QColor(colours.get(state, "#e01b24")))
    painter.setPen(Qt.NoPen)

    # Shield shape: the same as the Linux version.
    from PySide6.QtGui import QPainterPath
    path = QPainterPath()
    path.moveTo(size / 2, 2)
    path.lineTo(size - 4, 8)
    path.lineTo(size - 4, size * 0.55)
    path.quadTo(size - 4, size - 4, size / 2, size - 2)
    path.quadTo(4, size - 4, 4, size * 0.55)
    path.lineTo(4, 8)
    path.closeSubpath()
    painter.drawPath(path)
    painter.end()
    return QIcon(pixmap)


class Card(QFrame):
    def __init__(self, label: str) -> None:
        super().__init__()
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        self.caption = QLabel(label)
        self.caption.setObjectName("cardLabel")
        self.value = QLabel("—")
        self.value.setObjectName("cardValue")
        layout.addWidget(self.caption)
        layout.addWidget(self.value)


class Window(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.prefs = prefs.load()
        self.settings = Settings.load()
        set_language(self.prefs["language"] or detect())
        self.busy = False

        self.setWindowTitle(_("Steganon"))
        self.setStyleSheet(STYLE)
        self.resize(int(self.prefs["window_width"]) or 460, 700)

        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.outer.addWidget(self.scroll)

        # The icon is set up BEFORE the page is built: "_build_page" ends with
        # a status check that also updates the icon. If it does not exist yet,
        # the application crashes on start. The same mistake had been made in
        # the Linux version.
        self._build_tray()
        self._build_page()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(6000)

    # ── content ───────────────────────────────────────────────────────────

    def _build_page(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        layout.addWidget(self._build_hero())
        layout.addLayout(self._build_metrics())
        layout.addWidget(self._label(_("Priority order"), "groupTitle"))
        layout.addWidget(self._label(
            _("Top to bottom. If a location does not respond, the next one is tried."), "groupHint"))
        self.locations_box = QVBoxLayout()
        self.locations_box.setSpacing(6)
        layout.addLayout(self.locations_box)
        self._fill_locations()

        add = QPushButton("＋  " + _("Add location"))
        add.clicked.connect(self._on_add)
        layout.addWidget(add)

        layout.addWidget(self._label(_("Settings"), "groupTitle"))
        layout.addWidget(self._build_options())
        layout.addStretch(1)
        self.scroll.setWidget(page)
        self.refresh()

    def _label(self, text: str, name: str = "") -> QLabel:
        label = QLabel(text)
        if name:
            label.setObjectName(name)
        label.setWordWrap(True)
        return label

    def _build_hero(self) -> QWidget:
        self.hero = QFrame()
        self.hero.setObjectName("hero")
        layout = QVBoxLayout(self.hero)
        layout.setSpacing(12)

        top = QHBoxLayout()
        self.dot = QLabel()
        self.dot.setObjectName("dot")
        top.addWidget(self.dot, 0, Qt.AlignTop)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.title = QLabel(_("Checking…"))
        self.title.setObjectName("heroTitle")
        self.detail = QLabel("")
        self.detail.setObjectName("heroDetail")
        self.detail.setWordWrap(True)
        titles.addWidget(self.title)
        titles.addWidget(self.detail)
        top.addLayout(titles, 1)
        layout.addLayout(top)

        self.action = QPushButton(_("Connect"))
        self.action.setObjectName("action")
        self.action.setMinimumHeight(40)
        self.action.clicked.connect(self._on_action)
        layout.addWidget(self.action)
        return self.hero

    def _build_metrics(self) -> QGridLayout:
        grid = QGridLayout()
        grid.setSpacing(8)
        self.cards = {
            "ip": Card(_("ADDRESS")), "server": Card(_("SERVER")),
            "latency": Card(_("LATENCY")), "firewall": Card(_("FIREWALL")),
        }
        grid.addWidget(self.cards["ip"], 0, 0)
        grid.addWidget(self.cards["server"], 0, 1)
        grid.addWidget(self.cards["latency"], 1, 0)
        grid.addWidget(self.cards["firewall"], 1, 1)
        return grid

    def _fill_locations(self) -> None:
        while self.locations_box.count():
            item = self.locations_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for index, loc in enumerate(self.settings.locations):
            row = QFrame()
            row.setObjectName("row")
            layout = QHBoxLayout(row)
            layout.setContentsMargins(10, 6, 10, 6)

            rank = QLabel(str(index + 1))
            rank.setObjectName("rank")
            rank.setFixedWidth(18)
            layout.addWidget(rank)
            layout.addWidget(QLabel(loc.flag))

            # A location that will fail for want of a password says so here,
            # rather than at the moment failover reaches it.
            missing = loc.needs_auth and not loc.has_credentials
            titles = QVBoxLayout()
            titles.setSpacing(0)
            name = QLabel(loc.label)
            name.setObjectName("rowTitle")
            sub = QLabel(loc.remote if not missing
                         else f"{loc.remote}  ·  {_('No credentials yet')}")
            sub.setObjectName("rowSub")
            titles.addWidget(name)
            titles.addWidget(sub)
            layout.addLayout(titles, 1)

            # The credentials belong to this location, so the way to set them
            # is on this row — not in a button that would have to ask which.
            key = QToolButton()
            key.setText("🔑")
            key.setToolTip(_("Set credentials"))
            key.clicked.connect(lambda _c=False, n=loc.name: self._on_credentials(n))
            layout.addWidget(key)

            enabled = QCheckBox()
            enabled.setChecked(loc.enabled)
            enabled.toggled.connect(lambda state, n=loc.name: self._on_toggle(n, state))
            layout.addWidget(enabled)

            for symbol, delta, ok in (("▲", -1, index > 0),
                                      ("▼", +1, index < len(self.settings.locations) - 1)):
                button = QToolButton()
                button.setText(symbol)
                button.setEnabled(ok)
                button.clicked.connect(lambda _c=False, n=loc.name, d=delta: self._on_move(n, d))
                layout.addWidget(button)

            drop = QToolButton()
            drop.setText("🗑")
            drop.setEnabled(len(self.settings.locations) > 1)
            drop.clicked.connect(lambda _c=False, n=loc.name: self._on_remove(n))
            layout.addWidget(drop)

            self.locations_box.addWidget(row)

    def _build_options(self) -> QWidget:
        box = QFrame()
        box.setObjectName("card")
        layout = QVBoxLayout(box)
        layout.setSpacing(10)

        self.ipv6 = QCheckBox(_("Block IPv6"))
        self.ipv6.setChecked(self.settings.block_ipv6)
        self.ipv6.toggled.connect(lambda v: self._on_option("block_ipv6", v))
        layout.addWidget(self.ipv6)
        layout.addWidget(self._label(
            _("The provider's tunnel carries IPv4 only; without blocking, IPv6 traffic bypasses it."), "groupHint"))

        self.autostart = QCheckBox(_("Connect at startup"))
        self.autostart.setChecked(self.settings.autostart)
        self.autostart.toggled.connect(self._on_autostart)
        layout.addWidget(self.autostart)
        layout.addWidget(self._label(
            _("The firewall loads before the network on every boot, and the icon appears in the tray."), "groupHint"))

        language = QHBoxLayout()
        language.addWidget(QLabel(_("Language")))
        language.addStretch(1)
        self.language = QComboBox()
        self.codes = list(LANGUAGES)
        self.language.addItems([LANGUAGES[c] for c in self.codes])
        self.language.setCurrentIndex(self.codes.index(get_language()))
        self.language.currentIndexChanged.connect(self._on_language)
        language.addWidget(self.language)
        layout.addLayout(language)

        return box

    # ── tray icon ─────────────────────────────────────────────────────────

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(_tray_pixmap("off"), self)
        menu = QMenu()

        show = QAction(_("Steganon"), self)
        show.triggered.connect(self._toggle_window)
        menu.addAction(show)
        menu.addSeparator()

        quit_action = QAction(_("Quit"), self)
        quit_action.triggered.connect(self._on_quit)
        menu.addAction(quit_action)

        shutdown = QAction(_("Shut down protection…"), self)
        shutdown.triggered.connect(self._on_shutdown)
        menu.addAction(shutdown)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self._toggle_window()
            if reason == QSystemTrayIcon.Trigger else None
        )
        self.tray.show()

    def _toggle_window(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def closeEvent(self, event) -> None:
        """Closing hides the window, it does not stop the protection."""
        if self.tray.isVisible():
            self.hide()
            event.ignore()
        else:
            event.accept()

    # ── actions ───────────────────────────────────────────────────────────

    def _on_action(self) -> None:
        connected = monitor.check(self.settings).healthy
        self._set_busy(_("Disconnecting…") if connected else _("Connecting…"))
        QTimer.singleShot(100, lambda: self._do_action(connected))

    def _do_action(self, connected: bool) -> None:
        ok, output = _run_privileged("down" if connected else "up")
        self.busy = False
        if not ok:
            self._notify((output.splitlines() or [_("Failed")])[-1].strip())
        self.refresh()

    def _on_move(self, name: str, delta: int) -> None:
        if self.settings.move(name, delta):
            self._save_order()
            self._fill_locations()

    def _on_toggle(self, name: str, state: bool) -> None:
        for loc in self.settings.locations:
            if loc.name == name:
                loc.enabled = state
        self._save_order()

    def _on_option(self, field: str, value: bool) -> None:
        setattr(self.settings, field, value)
        self._save_order()

    def _on_autostart(self, value: bool) -> None:
        from .backends import windows_service as service
        self.settings.autostart = value
        service.set_gui_autostart(value)
        _run_privileged("autostart", "on" if value else "off")

    def _on_language(self, index: int) -> None:
        code = self.codes[index]
        if code == get_language():
            return
        set_language(code)
        prefs.save(language=code)
        self.setWindowTitle(_("Steganon"))
        self._build_page()

    def _save_order(self) -> None:
        ok, _out = _run_privileged("order", "--set",
                                   *[loc.name for loc in self.settings.locations])
        if not ok:
            self._notify(_("The change was not saved."))

    def _on_add(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, _("Choose a .ovpn file"), "", "OpenVPN (*.ovpn)")
        if not path:
            return
        ok, output = _run_privileged("add", path)
        if ok:
            self.settings = Settings.load()
            self._build_page()
            self._notify(_("Location added."))
        else:
            self._notify((output.splitlines() or [_("Failed")])[-1].strip())

    def _on_remove(self, name: str) -> None:
        answer = QMessageBox.question(
            self, _("Remove “{name}”?", name=pretty(name)),
            _("The location's certificates will be deleted."),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        ok, output = _run_privileged("remove", name)
        if ok:
            self.settings = Settings.load()
            self._build_page()
            self._notify(_("Location removed."))
        else:
            self._notify((output.splitlines() or [_("Failed")])[-1].strip())

    def _on_credentials(self, name: str) -> None:
        """Asks for one location's username and password.

        Per location, because providers disagree: some issue a single pair for
        the account, others a different one per server. Asking from the row
        removes the question of which location it applies to.
        """
        location = self.settings.find(name)
        if location is None:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(_("Credentials for {name}", name=location.label))
        dialog.setStyleSheet(STYLE)
        layout = QVBoxLayout(dialog)
        layout.addWidget(self._label(
            _("The pair your provider issues for manual setup — not your account password."), "groupHint"))
        layout.addWidget(self._label(
            _("Each location has its own username and password. Some providers issue one pair for the whole account, others a different pair per server."), "groupHint"))
        username = QLineEdit()
        username.setPlaceholderText(_("Username"))
        password = QLineEdit()
        password.setPlaceholderText(_("Password"))
        password.setEchoMode(QLineEdit.Password)
        layout.addWidget(username)
        layout.addWidget(password)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.Accepted:
            return
        if not username.text().strip() or not password.text():
            self._notify(_("Both fields are required."))
            return
        # From standard input, never as an argument: anything on a command
        # line is visible to every user of the machine.
        ok, output = _run_privileged(
            "credentials", name, "--stdin",
            text=f"{username.text().strip()}\n{password.text()}\n")
        if ok:
            # Re-read from disk so the row loses its "no credentials" note.
            self.settings = Settings.load()
            self._build_page()
            self._notify(_("Saved."))
        else:
            self._notify((output.splitlines() or [_("Failed")])[-1].strip())

    def _on_quit(self) -> None:
        if monitor.check(self.settings).healthy:
            answer = QMessageBox.question(
                self, _("Quit the application?"),
                _("The connection and firewall stay active. This window is only the front end — protection runs as a system service.\n\nTo actually stop protection, press “Disconnect” first."),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        self.tray.hide()
        QApplication.quit()

    def _on_shutdown(self) -> None:
        answer = QMessageBox.warning(
            self, _("Shut down protection?"),
            _("The connection, firewall and service will all stop. The machine will reach the internet **with no protection**, with your real address visible."),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self._set_busy(_("Disconnecting…"))
        _run_privileged("down", "--service")
        self.tray.hide()
        QApplication.quit()

    # ── refresh ───────────────────────────────────────────────────────────

    def _set_busy(self, message: str) -> None:
        self.busy = True
        self._style("working")
        self.title.setText(message)
        self.detail.setText("")
        self.action.setEnabled(False)

    def _style(self, state: str) -> None:
        for widget in (self.hero, self.dot):
            widget.setProperty("state", state)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def _tick(self) -> None:
        if not self.busy:
            self.refresh()

    def refresh(self) -> None:
        if self.busy:
            return
        health = monitor.check(self.settings)
        active = firewall.is_active()

        if health.healthy:
            state, title = "on", _("Protected")
            self.detail.setText(_("All traffic goes through the tunnel."))
            self.action.setText(_("Disconnect"))
            self.action.setProperty("mode", "leave")
        elif health.foreign_tunnel:
            state, title = "working", _("Another connection")
            self.detail.setText(_("A VPN is up, but Steganon does not control it. Without the firewall there is no guarantee if it drops."))
            self.action.setText(_("Take control"))
            self.action.setProperty("mode", "connect")
        else:
            state, title = "off", _("Exposed")
            self.detail.setText(_(health.detail) if health.detail
                                else _("Traffic is not going through a tunnel."))
            self.action.setText(_("Connect"))
            self.action.setProperty("mode", "connect")

        self.title.setText(title)
        self._style(state)
        self.action.style().unpolish(self.action)
        self.action.style().polish(self.action)
        self.action.setEnabled(True)

        self.cards["ip"].value.setText(health.external_ip or "—")
        server = tunnel.current_server() or "—"
        current = next(iter(self.settings.enabled_locations()), None)
        self.cards["server"].value.setText(
            f"{current.flag if current else ''} {server.split('.')[0]}".strip()
            if server != "—" else "—")
        self.cards["latency"].value.setText(
            f"{health.latency_ms:.0f} ms" if health.latency_ms else "—")
        self.cards["firewall"].value.setText(_("on") if active else _("off"))

        tray = getattr(self, "tray", None)
        if tray is not None:
            tray.setIcon(_tray_pixmap(state))
            label = f"{current.flag} {current.label}" if current else ""
            tray.setToolTip(f"{title} — {label}" if health.healthy and label else title)

    def _notify(self, message: str) -> None:
        self.tray.showMessage(_("Steganon"), message, QSystemTrayIcon.Information, 4000)


def main() -> int:
    app = QApplication([a for a in sys.argv if a != "--hidden"])
    app.setQuitOnLastWindowClosed(False)   # closing hides, it does not quit

    window = Window()
    if "--hidden" not in sys.argv:
        window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
