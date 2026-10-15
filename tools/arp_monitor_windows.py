#!/usr/bin/env python3
"""
arp_monitor_windows.py - Watch `arp -a` for MAC address changes and alert on Windows.

Baseline = MAC seen for each IP on the first run. Later runs are compared
against it. On a change you get a beep plus an always-on-top pop-up window.

Usage:
  python arp_monitor_windows.py                 # watch default gateway (recommended)
  python arp_monitor_windows.py --ip 10.0.0.1   # watch a specific IP
  python arp_monitor_windows.py --all           # watch every dynamic IP in the ARP table
  python arp_monitor_windows.py --interval 2 --log arp_monitor.log

No extra packages needed (standard library only). Admin rights not required.
Run with pythonw.exe instead of python.exe to hide the console window.
"""

import argparse
import ctypes
import re
import subprocess
import sys
import threading
import time
import winsound
from datetime import datetime

# Windows `arp -a` line:   192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic
ARP_RE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+"
    r"(?P<type>\w+)",
    re.MULTILINE,
)

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW: don't flash console windows

# MessageBox flags: warning icon + always on top + system modal
MB_FLAGS = 0x30 | 0x40000 | 0x1000


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                          timeout=15, creationflags=NO_WINDOW).stdout


def get_arp_table(include_static=False):
    """Return {ip: mac} from `arp -a`. MACs normalized to aa:bb:cc:dd:ee:ff.
    Skips static entries (broadcast/multicast) unless include_static=True."""
    try:
        out = run(["arp", "-a"])
    except subprocess.TimeoutExpired:
        return {}
    table = {}
    for m in ARP_RE.finditer(out):
        if m["type"].lower() != "dynamic" and not include_static:
            continue
        mac = m["mac"].lower().replace("-", ":")
        if mac == "ff:ff:ff:ff:ff:ff":
            continue
        table[m["ip"]] = mac
    return table


def get_default_gateway():
    """Parse the 0.0.0.0 route from `route print`; pick the lowest metric."""
    out = run(["route", "print", "-4", "0.0.0.0"])
    best = None
    for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+[\d.]+\s+(\d+)",
                         out, re.MULTILINE):
        gw, metric = m.group(1), int(m.group(2))
        if best is None or metric < best[1]:
            best = (gw, metric)
    return best[0] if best else None


def ping(ip):
    """Ping once so the IP has a fresh ARP entry."""
    subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   creationflags=NO_WINDOW)


def alert(title, message):
    """Beep + pop-up in a separate thread so monitoring keeps running."""
    def _show():
        try:
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except RuntimeError:
            pass
        ctypes.windll.user32.MessageBoxW(0, message, title, MB_FLAGS)
    threading.Thread(target=_show, daemon=True).start()


def log(msg, logfile):
    line = f"[{now()}] {msg}"
    try:
        print(line, flush=True)
    except (OSError, AttributeError):
        pass  # no console under pythonw.exe
    if logfile:
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def main():
    if sys.platform != "win32":
        sys.exit("This version is for Windows. Use arp_monitor_linux.py on Linux.")

    p = argparse.ArgumentParser(description="Alert when a MAC in the ARP table changes.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ip", help="Specific IP to watch")
    g.add_argument("--all", action="store_true", help="Watch every dynamic IP in the ARP table")
    p.add_argument("--interval", type=float, default=5, help="Seconds between checks (default 5)")
    p.add_argument("--log", help="Optional log file path")
    args = p.parse_args()

    target = None
    if not args.all:
        target = args.ip or get_default_gateway()
        if not target:
            sys.exit("Couldn't find default gateway. Use --ip <addr> or --all.")

    # ---- Baseline ----
    if target:
        ping(target)
    table = get_arp_table(include_static=bool(target))
    if target:
        if target not in table:
            sys.exit(f"{target} not in ARP table. Is it reachable?")
        baseline = {target: table[target]}
    else:
        if not table:
            sys.exit("ARP table has no dynamic entries.")
        baseline = dict(table)

    last_seen = dict(baseline)
    log(f"Baseline captured ({len(baseline)} entr{'y' if len(baseline) == 1 else 'ies'}):", args.log)
    for ip, mac in baseline.items():
        log(f"  {ip:<16} {mac}", args.log)
    log(f"Checking every {args.interval}s. Ctrl+C to stop.", args.log)

    # ---- Loop ----
    try:
        while True:
            time.sleep(args.interval)
            if target:
                ping(target)
            table = get_arp_table(include_static=bool(target))

            for ip, mac in table.items():
                if ip not in baseline:
                    if args.all:  # new device: add to baseline, just log it
                        baseline[ip] = last_seen[ip] = mac
                        log(f"New entry: {ip} -> {mac}", args.log)
                    continue

                if mac != last_seen[ip]:
                    msg = (f"IP: {ip}\n"
                           f"Original MAC: {baseline[ip]}\n"
                           f"Previous MAC: {last_seen[ip]}\n"
                           f"Current MAC:  {mac}\n"
                           f"Time: {now()}")
                    if mac == baseline[ip]:
                        title = "QuickSentry Lite: MAC reverted to original"
                    else:
                        title = "QuickSentry Lite: MAC ADDRESS CHANGED"
                    log(f"{title} | {msg.replace(chr(10), ' | ')}", args.log)
                    alert(title, msg)
                    last_seen[ip] = mac
    except KeyboardInterrupt:
        log("Stopped.", args.log)


if __name__ == "__main__":
    main()
