"""Where QuickSentry keeps its files, plus settings / known-network persistence.

Since v3 QuickSentry always runs as administrator, so everything lives in
%ProgramData%\\QuickSentry, locked to SYSTEM + Administrators. A standard user
(or malware running as one) can't edit the baseline or wipe the logs.
Data from older versions (%APPDATA%\\QuickSentry, %APPDATA%\\ArpWatch, or a
portable QuickSentry-data folder next to the exe) is copied over once.
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
    # --- guard (v3) ---
    "guard_speed_trap": True,      # freeze typing on robot-speed keystrokes
    "guard_defender": True,        # run Microsoft Defender on new drives
    "guard_autoplay": True,        # NoDriveTypeAutoRun = 0xFF
    "guard_strict": False,         # mountvol /N (new volumes get no letter)
    "guard_policies": {},          # category -> log|alert|ask|block (defaults in guard.hardware)
    "guard_blocked": [],           # remembered blocked devices (VID:PID)
    "guard_trusted": [],           # device instance IDs allowed permanently
    "watch_connections": True,     # listeners / inbound sessions / firewall changes
    "trusted_ips": [],             # inbound sources you've marked as expected
}

_lock = threading.Lock()


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


_ready = set()


def data_dir():
    override = os.environ.get("QUICKSENTRY_DATA")          # tests / demo mode
    if override:
        d = override
    else:
        base = os.environ.get("ProgramData") or os.path.expanduser("~")
        d = os.path.join(base, "QuickSentry")
    if d in _ready:
        return d
    first = not os.path.isdir(d)
    for sub in ("", "logs", "reports"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    if first and not override:
        _lock_down(d)
        appdata = os.environ.get("APPDATA") or ""
        for old in (os.path.join(appdata, "QuickSentry"), os.path.join(appdata, "ArpWatch"),
                    os.path.join(app_dir(), "QuickSentry-data"), os.path.join(app_dir(), "ArpWatch-data")):
            if appdata and os.path.isdir(old):
                _migrate(old, d)
                break
    _ready.add(d)
    return d


def _lock_down(d):
    """SYSTEM + Administrators only (no-op off Windows or without admin)."""
    if sys.platform == "win32" and winapi.is_admin():
        winapi.run(["icacls", d, "/inheritance:r", "/grant:r",
                    "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])


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
