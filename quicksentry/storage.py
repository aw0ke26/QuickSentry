"""Where QuickSentry keeps its files, plus settings / known-network persistence.

Portable mode (data stored next to the exe) is used when:
  - the exe/script is on a removable drive (USB flash drive), or
  - a file named 'portable.txt' or a folder 'QuickSentry-data' sits next to it.
Otherwise data goes to %APPDATA%\\QuickSentry.
"""

import json
import os
import sys
import threading
import time

from . import winapi

DEFAULT_SETTINGS = {
    "interval": 5,                 # seconds between fast checks
    "check_wifi": True,
    "check_first_hop": True,
    "check_ipv6": True,
    "check_web": True,             # captive portal + HTTPS + DNS checks
    "web_interval": 300,           # seconds between web checks
    "popups": True,
    "sound": True,
    "minimize_to_tray": True,
    "autostart_monitoring": True,
    "path_targets": "",
    "path_interval": 60,
    "scan_range": "",
}

_lock = threading.Lock()


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_portable():
    d = app_dir()
    return (winapi.drive_is_removable(d)
            or os.path.exists(os.path.join(d, "portable.txt"))
            or os.path.isdir(os.path.join(d, "QuickSentry-data"))
            or os.path.isdir(os.path.join(d, "ArpWatch-data")))


def data_dir():
    if is_portable():
        d = os.path.join(app_dir(), "QuickSentry-data")
        old = os.path.join(app_dir(), "ArpWatch-data")
    else:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "QuickSentry")
        old = os.path.join(base, "ArpWatch")
    if not os.path.isdir(d) and os.path.isdir(old):
        _migrate(old, d)       # carry over data from the ARP Watch name
    for sub in ("", "logs", "reports"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    return d


def _migrate(old, new):
    import shutil
    try:
        os.makedirs(new, exist_ok=True)
        for name in ("settings.json", "known_networks.json"):
            src = os.path.join(old, name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(new, name))
    except OSError:
        pass


def _path(name):
    return os.path.join(data_dir(), name)


def _load_json(name, default):
    try:
        with open(_path(name), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save_json(name, obj):
    with _lock:
        tmp = _path(name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, _path(name))


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    s.update(_load_json("settings.json", {}))
    return s


def save_settings(s):
    _save_json("settings.json", s)


def load_known_networks():
    return _load_json("known_networks.json", {})


def save_known_networks(k):
    _save_json("known_networks.json", k)


def log_line(text):
    """Append to today's log file."""
    try:
        name = time.strftime("alerts-%Y-%m-%d.log")
        with _lock, open(os.path.join(data_dir(), "logs", name), "a", encoding="utf-8") as f:
            f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + text + "\n")
    except OSError:
        pass


def reports_dir():
    return os.path.join(data_dir(), "reports")
