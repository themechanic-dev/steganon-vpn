"""Languages.

A small dictionary instead of gettext: the language changes inside the running
application, with no restart and no compiled catalogues to keep in sync. For
two languages and a few hundred phrases a plain dict is easier to read — and
easier for anyone who spots a bad translation to fix.

English is the source language; the keys below are the English strings, so the
code reads without the dictionary next to it. The interface follows the
system's language and the user can override it.
"""

from __future__ import annotations

import os

LANGUAGES = {"en": "English", "el": "Ελληνικά"}
DEFAULT = "en"

_current = DEFAULT

TRANSLATIONS: dict[str, dict[str, str]] = {
    # ── the name ──────────────────────────────────────────────────────────
    # Transliterated rather than translated: «Στεγανό» is the watertight
    # compartment of a ship, the one that will not let water through. The
    # English form keeps the sound, not the meaning, as product names do.
    "Steganon": {"el": "Στεγανό"},

    # ── states ────────────────────────────────────────────────────────────
    "Protected": {"el": "Προστατευμένο"},
    "Exposed": {"el": "Εκτεθειμένο"},
    "Another connection": {"el": "Άλλη σύνδεση"},
    "Checking…": {"el": "Έλεγχος…"},
    "Connecting…": {"el": "Σύνδεση…"},
    "Disconnecting…": {"el": "Αποσύνδεση…"},
    "All traffic goes through the tunnel.": {"el": "Όλη η κίνηση περνά από το tunnel."},
    "Traffic is not going through a tunnel.": {"el": "Η κίνηση δεν περνά από tunnel."},
    "A VPN is up, but Steganon does not control it. Without the firewall there is no guarantee if it drops.":
        {"el": "Υπάρχει VPN που δεν το ελέγχει το Στεγανό. Χωρίς τείχος δεν "
               "υπάρχει εγγύηση αν πέσει."},

    # ── buttons ───────────────────────────────────────────────────────────
    "Connect": {"el": "Σύνδεση"},
    "Disconnect": {"el": "Αποσύνδεση"},
    "Take control": {"el": "Ανάληψη ελέγχου"},
    "Measure latency": {"el": "Μέτρηση απόκρισης"},
    "Refresh": {"el": "Ανανέωση"},
    "Language": {"el": "Γλώσσα"},

    # ── cards ─────────────────────────────────────────────────────────────
    "ADDRESS": {"el": "ΔΙΕΥΘΥΝΣΗ"},
    "SERVER": {"el": "SERVER"},
    "LATENCY": {"el": "ΑΠΟΚΡΙΣΗ"},
    "FIREWALL": {"el": "ΤΕΙΧΟΣ"},
    "on": {"el": "ενεργό"},
    "off": {"el": "ανενεργό"},

    # ── locations & settings ──────────────────────────────────────────────
    "Priority order": {"el": "Σειρά προτεραιότητας"},
    "Top to bottom. If a location does not respond, the next one is tried.":
        {"el": "Από πάνω προς τα κάτω. Αν μια τοποθεσία δεν απαντά, δοκιμάζεται "
               "η επόμενη."},
    "Settings": {"el": "Ρυθμίσεις"},
    "Block IPv6": {"el": "Φραγή IPv6"},
    "The provider's tunnel carries IPv4 only; without blocking, IPv6 traffic bypasses it.":
        {"el": "Το tunnel του παρόχου μεταφέρει μόνο IPv4· χωρίς φραγή η κίνηση "
               "IPv6 το παρακάμπτει."},
    "Connect at startup": {"el": "Σύνδεση στην εκκίνηση"},
    "The firewall loads before the network on every boot.":
        {"el": "Το τείχος ενεργοποιείται πριν από το δίκτυο σε κάθε άναμμα."},
    "The firewall loads before the network on every boot, and the icon appears in the tray.":
        {"el": "Το τείχος ενεργοποιείται πριν από το δίκτυο σε κάθε άναμμα, και "
               "το εικονίδιο εμφανίζεται στη μπάρα."},

    "Add location": {"el": "Προσθήκη τοποθεσίας"},
    "Remove": {"el": "Αφαίρεση"},
    "Cancel": {"el": "Άκυρο"},
    "Choose a .ovpn file": {"el": "Επιλογή αρχείου .ovpn"},
    "Remove “{name}”?": {"el": "Αφαίρεση «{name}»;"},
    "The location's certificates will be deleted.":
        {"el": "Τα πιστοποιητικά της τοποθεσίας θα διαγραφούν."},
    "Location added.": {"el": "Η τοποθεσία προστέθηκε."},
    "Location removed.": {"el": "Η τοποθεσία αφαιρέθηκε."},

    "Quit": {"el": "Έξοδος"},
    "Quit the application?": {"el": "Έξοδος από την εφαρμογή;"},
    "The connection and firewall stay active. This window is only the front end — protection runs as a system service.\n\nTo actually stop protection, press “Disconnect” first.":
        {"el": "Η σύνδεση και το τείχος παραμένουν ενεργά. Το παράθυρο είναι μόνο "
               "η όψη — η προστασία τρέχει ως υπηρεσία του συστήματος.\n\nΓια να "
               "διακόψεις πραγματικά την προστασία, πάτησε πρώτα «Αποσύνδεση»."},
    "Shut down protection…": {"el": "Τερματισμός προστασίας…"},
    "Shut down protection?": {"el": "Τερματισμός προστασίας;"},
    "The connection, firewall and service will all stop. The machine will reach the internet **with no protection**, with your real address visible.":
        {"el": "Θα κλείσουν η σύνδεση, το τείχος και η υπηρεσία. Το μηχάνημα θα "
               "βγαίνει στο internet **χωρίς προστασία**, με την πραγματική σου "
               "διεύθυνση ορατή."},
    "Do not start on next boot either": {"el": "Να μην ξεκινά ούτε στο επόμενο άναμμα"},
    "Shut down": {"el": "Τερματισμός"},
    "Shutting down…": {"el": "Τερματισμός…"},
    "Credentials for {name}": {"el": "Διαπιστευτήρια για {name}"},
    "Set credentials": {"el": "Ορισμός διαπιστευτηρίων"},
    "No credentials yet": {"el": "Χωρίς διαπιστευτήρια"},
    "Each location has its own username and password. Some providers issue one pair for the whole account, others a different pair per server.":
        {"el": "Κάθε τοποθεσία έχει δικό της όνομα χρήστη και κωδικό. Κάποιοι "
               "πάροχοι δίνουν ένα ζεύγος για όλο τον λογαριασμό, άλλοι "
               "διαφορετικό ανά server."},
    "The pair your provider issues for manual setup — not your account password.":
        {"el": "Το ζεύγος που δίνει ο πάροχος για χειροκίνητη ρύθμιση — όχι ο "
               "κωδικός του λογαριασμού σου."},
    "Username": {"el": "Όνομα χρήστη"},
    "Password": {"el": "Κωδικός"},
    "Save": {"el": "Αποθήκευση"},
    "Saved.": {"el": "Αποθηκεύτηκαν."},
    "Both fields are required.": {"el": "Χρειάζονται και τα δύο πεδία."},

    # ── messages ──────────────────────────────────────────────────────────
    "Connected.": {"el": "Συνδέθηκε."},
    "Disconnected.": {"el": "Αποσυνδέθηκε."},
    "Failed": {"el": "Απέτυχε"},
    "Measuring…": {"el": "Μέτρηση…"},
    "Fastest: {name} ({ms:.0f} ms)": {"el": "Ταχύτερη: {name} ({ms:.0f} ms)"},
    "No location responded.": {"el": "Καμία τοποθεσία δεν απάντησε."},
    "The change was not saved.": {"el": "Η αλλαγή δεν αποθηκεύτηκε."},

    # ── diagnostics ───────────────────────────────────────────────────────
    "No tunnel interface.": {"el": "Δεν υπάρχει διεπαφή tunnel."},
    "Internet traffic is not routed through the tunnel.":
        {"el": "Η κίνηση προς το internet δεν περνά από το tunnel."},
    "A VPN connection exists, but Steganon does not control it.":
        {"el": "Υπάρχει σύνδεση VPN, αλλά δεν την ελέγχει το Στεγανό."},
    "The tunnel is up but no traffic passes through it.":
        {"el": "Το tunnel στέκει αλλά δεν περνά κίνηση."},
    "LEAK: the outbound address is your real one.":
        {"el": "ΔΙΑΡΡΟΗ: η διεύθυνση προς τα έξω είναι η πραγματική."},
    "No reference address known.": {"el": "Άγνωστη διεύθυνση αναφοράς."},
    "Very slow response.": {"el": "Πολύ αργή απόκριση."},
}


def country(name: str) -> str:
    """A location name, ready to show.

    Deliberately not a translation. Earlier versions carried a table of
    country names in Greek, which quietly decided which countries the program
    knew about — useless to anyone whose provider offers somewhere else. The
    name is the user's own, so it is shown as given.
    """
    from .config import pretty
    return pretty(name)


def set_language(code: str) -> None:
    global _current
    if code in LANGUAGES:
        _current = code


def get_language() -> str:
    return _current


def detect() -> str:
    """Guesses the language from the environment, falling back to English."""
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var, "")
        if value[:2] in LANGUAGES:
            return value[:2]
    return DEFAULT


def _(text: str, **kwargs) -> str:
    """Translates. The key is the English text, so the code stays readable
    without the dictionary beside it."""
    if _current == DEFAULT:
        out = text
    else:
        out = TRANSLATIONS.get(text, {}).get(_current, text)
    return out.format(**kwargs) if kwargs else out
