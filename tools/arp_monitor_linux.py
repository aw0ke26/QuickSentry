#!/usr/bin/env python3
"""
arp_monitor_linux.py - Watch `arp -a` for MAC address changes and alert on the desktop.

Baseline = MAC seen for each IP on the first run. Later runs are compared
against it. On a change you get a desktop notification plus a pop-up window.

Usage:
  python3 arp_monitor_linux.py                 # watch default gateway (recommended)
  python3 arp_monitor_linux.py --ip 10.0.0.1   # watch a specific IP
  python3 arp_monitor_linux.py --all           # watch every IP in the ARP table
  python3 arp_monitor_linux.py --interval 2 --log arp_monitor.log

Requires: net-tools (arp)        -> sudo apt install net-tools
Optional: zenity, libnotify-bin  -> sudo apt install zenity libnotify-bin
Run as your normal desktop user (not sudo) so the pop-ups can reach your screen.
"""

import argparse
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

ARP_RE = re.compile(r"\((?P<ip>[\d.]+)\) at (?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_arp_table():
    """Return {ip: mac} from `arp -a -n`. Skips <incomplete> entries."""
    try:
        out = subprocess.run(["arp", "-a", "-n"], capture_output=True,
                             text=True, timeout=10).stdout
    except FileNotFoundError:
        sys.exit("`arp` not found. Install it: sudo apt install net-tools")
    except subprocess.TimeoutExpired:
        return {}
    return {m["ip"]: m["mac"].lower() for m in ARP_RE.finditer(out)}


def get_default_gateway():
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True).stdout
        m = re.search(r"default via ([\d.]+)", out)
        return m.group(1) if m else None
    except FileNotFoundError:
        return None


def ping(ip):
    """Ping once so the IP has a fresh ARP entry."""
    subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def alert(title, message):
    # Desktop notification
    if shutil.which("notify-send"):
        subprocess.Popen(["notify-send", "-u", "critical", title, message])
    # Pop-up window (non-blocking so monitoring keeps running)
    if shutil.which("zenity"):
        subprocess.Popen(["zenity", "--warning", "--title", title,
                          "--text", message, "--width", "420"],
                         stderr=subprocess.DEVNULL)
    else:
        tk_code = (
            "import sys, tkinter as tk; from tkinter import messagebox;"
            "r=tk.Tk(); r.withdraw(); r.attributes('-topmost', True);"
            "messagebox.showwarning(sys.argv[1], sys.argv[2]); r.destroy()"
        )
        subprocess.Popen([sys.executable, "-c", tk_code, title, message])


def log(msg, logfile):
    line = f"[{now()}] {msg}"
    print(line, flush=True)
    if logfile:
        with open(logfile, "a") as f:
            f.write(line + "\n")


def main():
    p = argparse.ArgumentParser(description="Alert when a MAC in the ARP table changes.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ip", help="Specific IP to watch")
    g.add_argument("--all", action="store_true", help="Watch every IP in the ARP table")
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
    table = get_arp_table()
    if target:
        if target not in table:
            sys.exit(f"{target} not in ARP table. Is it reachable?")
        baseline = {target: table[target]}
    else:
        if not table:
            sys.exit("ARP table is empty.")
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
            table = get_arp_table()

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
