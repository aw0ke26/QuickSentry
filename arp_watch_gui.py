#!/usr/bin/env python3
"""
arp_watch_gui.py - Windows GUI for ARP / MAC address change monitoring.

Start/Stop monitoring of `arp -a`. Baseline = MAC per IP when you press Start.
Any later change triggers a beep + always-on-top pop-up and is highlighted in
the table and log.

Build to .exe (on Windows):
  python -m pip install pyinstaller
  python -m PyInstaller --onefile --windowed --name ArpWatch arp_watch_gui.py
  -> dist\\ArpWatch.exe
"""

import ctypes
import ipaddress
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

try:
    import winsound
except ImportError:  # lets the file be opened/tested off Windows
    winsound = None

APP_NAME = "ARP Watch"

# Windows `arp -a` line:   192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic
ARP_RE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+"
    r"(?P<type>\w+)",
    re.MULTILINE,
)
NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
MB_FLAGS = 0x30 | 0x40000 | 0x1000  # warning icon | topmost | system modal


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                          timeout=15, creationflags=NO_WINDOW).stdout


def get_arp_table(include_static=False):
    """Return {ip: mac} from `arp -a`, MACs as aa:bb:cc:dd:ee:ff."""
    try:
        out = run(["arp", "-a"])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}
    table = {}
    for m in ARP_RE.finditer(out):
        if m["type"].lower() != "dynamic" and not include_static:
            continue
        mac = m["mac"].lower().replace("-", ":")
        if mac != "ff:ff:ff:ff:ff:ff":
            table[m["ip"]] = mac
    return table


def get_default_gateway():
    """Lowest-metric 0.0.0.0 route from `route print`."""
    try:
        out = run(["route", "print", "-4", "0.0.0.0"])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    best = None
    for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+[\d.]+\s+(\d+)",
                         out, re.MULTILINE):
        gw, metric = m.group(1), int(m.group(2))
        if best is None or metric < best[1]:
            best = (gw, metric)
    return best[0] if best else None


def ping(ip):
    subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   creationflags=NO_WINDOW)


def popup_alert(title, message):
    """Beep + native pop-up on its own thread so nothing blocks."""
    def _show():
        if winsound:
            try:
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except RuntimeError:
                pass
        if sys.platform == "win32":
            ctypes.windll.user32.MessageBoxW(0, message, title, MB_FLAGS)
    threading.Thread(target=_show, daemon=True).start()


# --------------------------------------------------------------------------
# Monitor thread (never touches tkinter; talks to the GUI through a queue)
# --------------------------------------------------------------------------
class Monitor(threading.Thread):
    def __init__(self, mode, ip, interval, q):
        super().__init__(daemon=True)
        self.mode, self.ip, self.interval, self.q = mode, ip, interval, q
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def emit(self, *event):
        self.q.put(event)

    def run(self):
        try:
            self._run()
        except Exception as e:  # keep the GUI alive no matter what
            self.emit("error", f"Unexpected error: {e}")
        finally:
            self.emit("stopped")

    def _run(self):
        target = None
        if self.mode == "gateway":
            self.emit("log", "Detecting default gateway...")
            target = get_default_gateway()
            if not target:
                self.emit("error", "Couldn't find a default gateway. "
                                   "Use 'Specific IP' or 'All entries'.")
                return
            self.emit("log", f"Default gateway: {target}")
        elif self.mode == "ip":
            target = self.ip

        # Baseline
        if target:
            ping(target)
        table = get_arp_table(include_static=bool(target))
        if target:
            if target not in table:
                self.emit("error", f"{target} is not in the ARP table. Is it reachable?")
                return
            baseline = {target: table[target]}
        else:
            if not table:
                self.emit("error", "ARP table has no dynamic entries.")
                return
            baseline = dict(table)

        last_seen = dict(baseline)
        self.emit("log", f"Baseline captured ({len(baseline)} entries).")
        for ip, mac in baseline.items():
            self.emit("row", ip, mac, mac, "OK")
            self.emit("log", f"  {ip:<16} {mac}")
        self.emit("running", target or "all entries")

        # Loop; wait() returns True as soon as Stop is pressed
        while not self.stop_event.wait(self.interval):
            if target:
                ping(target)
            table = get_arp_table(include_static=bool(target))

            for ip, mac in table.items():
                if ip not in baseline:
                    if target is None:
                        baseline[ip] = last_seen[ip] = mac
                        self.emit("row", ip, mac, mac, "New")
                        self.emit("log", f"New entry: {ip} -> {mac}")
                    continue

                if mac != last_seen[ip]:
                    reverted = mac == baseline[ip]
                    title = ("ARP Watch: MAC reverted to original" if reverted
                             else "ARP Watch: MAC ADDRESS CHANGED")
                    msg = (f"IP: {ip}\n"
                           f"Original MAC: {baseline[ip]}\n"
                           f"Previous MAC: {last_seen[ip]}\n"
                           f"Current MAC:  {mac}\n"
                           f"Time: {now()}")
                    self.emit("row", ip, baseline[ip], mac,
                              "Reverted" if reverted else "CHANGED")
                    self.emit("log", f"{title} | " + msg.replace("\n", " | "))
                    popup_alert(title, msg)
                    last_seen[ip] = mac

            self.emit("tick")


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("720x520")
        self.minsize(600, 420)
        self.q = queue.Queue()
        self.monitor = None
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(200, self.poll_queue)

    def _build(self):
        pad = {"padx": 8, "pady": 4}

        # Settings
        settings = ttk.LabelFrame(self, text="Settings")
        settings.pack(fill="x", **pad)

        self.mode = tk.StringVar(value="gateway")
        ttk.Radiobutton(settings, text="Default gateway (recommended)", value="gateway",
                        variable=self.mode, command=self._mode_changed).grid(
            row=0, column=0, sticky="w", **pad)
        ttk.Radiobutton(settings, text="Specific IP:", value="ip",
                        variable=self.mode, command=self._mode_changed).grid(
            row=0, column=1, sticky="w", **pad)
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(settings, textvariable=self.ip_var, width=16, state="disabled")
        self.ip_entry.grid(row=0, column=2, sticky="w", **pad)
        ttk.Radiobutton(settings, text="All entries", value="all",
                        variable=self.mode, command=self._mode_changed).grid(
            row=0, column=3, sticky="w", **pad)

        ttk.Label(settings, text="Check every (seconds):").grid(row=1, column=0, sticky="w", **pad)
        self.interval_var = tk.StringVar(value="5")
        ttk.Spinbox(settings, from_=1, to=3600, textvariable=self.interval_var,
                    width=8).grid(row=1, column=1, sticky="w", **pad)

        # Buttons + status
        bar = ttk.Frame(self)
        bar.pack(fill="x", **pad)
        self.start_btn = ttk.Button(bar, text="Start", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="Export log...", command=self.export_log).pack(side="right")
        self.status = tk.StringVar(value="Stopped")
        self.status_lbl = tk.Label(bar, textvariable=self.status, fg="gray30",
                                   font=("Segoe UI", 10, "bold"))
        self.status_lbl.pack(side="left", padx=12)

        # Table
        cols = ("ip", "baseline", "current", "status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=7)
        for col, text, w in zip(cols, ("IP Address", "Baseline MAC", "Current MAC", "Status"),
                                (140, 170, 170, 100)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("CHANGED", background="#f8d0d0")
        self.tree.tag_configure("Reverted", background="#fff2c2")
        self.tree.pack(fill="both", expand=False, **pad)

        # Log
        ttk.Label(self, text="Log").pack(anchor="w", padx=8)
        self.log_box = ScrolledText(self, height=10, state="disabled",
                                    font=("Consolas", 9))
        self.log_box.pack(fill="both", expand=True, **pad)

    def _mode_changed(self):
        self.ip_entry.config(state="normal" if self.mode.get() == "ip" else "disabled")

    def _set_running_ui(self, running):
        state = "disabled" if running else "normal"
        self.start_btn.config(state=state)
        self.stop_btn.config(state="normal" if running else "disabled")
        for child in self.winfo_children()[0].winfo_children():  # settings frame
            try:
                child.config(state=state)
            except tk.TclError:
                pass
        if not running:
            self._mode_changed()

    def log(self, msg):
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"[{now()}] {msg}\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def set_status(self, text, color):
        self.status.set(text)
        self.status_lbl.config(fg=color)

    # --- actions ---
    def start(self):
        try:
            interval = float(self.interval_var.get())
            if interval < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_NAME, "Interval must be a number, 1 second or more.")
            return

        ip = None
        if self.mode.get() == "ip":
            ip = self.ip_var.get().strip()
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                messagebox.showerror(APP_NAME, f"'{ip}' is not a valid IPv4 address.")
                return

        self.tree.delete(*self.tree.get_children())
        self._set_running_ui(True)
        self.set_status("Starting...", "darkorange")
        self.monitor = Monitor(self.mode.get(), ip, interval, self.q)
        self.monitor.start()

    def stop(self):
        if self.monitor:
            self.monitor.stop()
            self.stop_btn.config(state="disabled")
            self.set_status("Stopping...", "darkorange")

    def export_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            filetypes=[("Log files", "*.log"),
                                                       ("Text files", "*.txt")],
                                            initialfile="arp_watch.log")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_box.get("1.0", "end"))

    def on_close(self):
        if self.monitor and self.monitor.is_alive():
            if not messagebox.askyesno(APP_NAME, "Monitoring is running. Stop and exit?"):
                return
            self.monitor.stop()
        self.destroy()

    # --- events from the monitor thread ---
    def poll_queue(self):
        try:
            while True:
                event = self.q.get_nowait()
                kind = event[0]
                if kind == "log":
                    self.log(event[1])
                elif kind == "row":
                    _, ip, base, cur, status = event
                    vals = (ip, base, cur, status)
                    tags = (status,)
                    if self.tree.exists(ip):
                        self.tree.item(ip, values=vals, tags=tags)
                    else:
                        self.tree.insert("", "end", iid=ip, values=vals, tags=tags)
                elif kind == "running":
                    self.set_status(f"Monitoring {event[1]}", "green4")
                elif kind == "tick":
                    pass
                elif kind == "error":
                    self.log(f"ERROR: {event[1]}")
                    messagebox.showerror(APP_NAME, event[1])
                elif kind == "stopped":
                    self.log("Monitoring stopped.")
                    self.set_status("Stopped", "gray30")
                    self._set_running_ui(False)
                    self.monitor = None
        except queue.Empty:
            pass
        self.after(200, self.poll_queue)


if __name__ == "__main__":
    App().mainloop()
