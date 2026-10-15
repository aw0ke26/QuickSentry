"""ARP Watch GUI (tkinter)."""

import csv
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import APP_NAME, __version__, actions, oui, pathmon, scanner, storage, sysinfo, winapi
from .engine import ALERT, CHECKS, INFO, OFF, OK, UNKNOWN, WARN, Engine

# ---------------------------------------------------------------------------
# Look & feel
# ---------------------------------------------------------------------------
BANNER = {
    OK: ("#1e7e34", "white", "No signs of attack",
         "Monitoring this network. Tip: a VPN keeps you safe even if something goes wrong."),
    WARN: ("#e0a800", "#212529", "Something looks unusual",
           "Review the yellow items below. Avoid banking and logins unless you're on a VPN."),
    ALERT: ("#c82333", "white", "Possible attack detected",
            "Stop sensitive activity. Disconnect or turn on a VPN, then review the red items."),
    UNKNOWN: ("#5a6268", "white", "Not monitoring",
              "Press Start to begin checking this network."),
}
WORDS = {OK: "OK", INFO: "Info", WARN: "Caution", ALERT: "ALERT", UNKNOWN: "Checking...",
         OFF: "Off"}
ROW_BG = {OK: "#e6f4ea", INFO: "#eef2f7", WARN: "#fff3cd", ALERT: "#f8d7da",
          UNKNOWN: "#f4f4f4", OFF: "#f4f4f4"}
POPUP_COOLDOWN = 120


def fmt_time(t):
    return time.strftime("%H:%M:%S", time.localtime(t))


def open_folder(path):
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Background workers (never touch tkinter; post to the queue)
# ---------------------------------------------------------------------------
class MonitorThread(threading.Thread):
    def __init__(self, q, settings, known):
        super().__init__(daemon=True)
        self.q = q
        self.settings = settings
        self.engine = Engine(settings, known)
        self.stop_ev = threading.Event()
        self.cmds = queue.Queue()

    def stop(self):
        self.stop_ev.set()
        self.cmds.put("wake")

    def command(self, c):
        self.cmds.put(c)

    def run(self):
        while not self.stop_ev.is_set():
            try:
                snap, res, events = self.engine.step()
                self.q.put(("state", snap, dict(res), self.engine.overall(), events))
                if self.engine.known_dirty:
                    storage.save_known_networks(self.engine.known)
                    self.engine.known_dirty = False
            except Exception as e:
                self.q.put(("error", f"Monitoring error: {e}"))
            try:
                c = self.cmds.get(timeout=max(2, float(self.settings.get("interval", 5))))
                if c == "reset":
                    self.engine.reset_baseline()
                elif c == "recheck":
                    self.engine.force_recheck()
            except queue.Empty:
                pass
        self.q.put(("stopped",))


class PathThread(threading.Thread):
    def __init__(self, q, targets, interval):
        super().__init__(daemon=True)
        self.q, self.targets, self.interval = q, targets, interval
        self.stop_ev = threading.Event()

    def run(self):
        while not self.stop_ev.is_set():
            try:
                snap = sysinfo.snapshot(include_wifi_scan=False)
                net = sysinfo.local_subnet(snap)
                for t in self.targets:
                    if self.stop_ev.is_set():
                        break
                    self.q.put(("path_running", t.host))
                    ev = pathmon.run_target(t, snap.get("gateway_ip"), net,
                                            {**snap.get("neighbors4", {})})
                    self.q.put(("path", ev))
            except Exception as e:
                self.q.put(("error", f"Path monitor error: {e}"))
            self.stop_ev.wait(self.interval)
        self.q.put(("path_stopped",))


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.settings = storage.load_settings()
        self.known = storage.load_known_networks()
        self.title(f"{APP_NAME} {__version__}")
        self.geometry("980x700")
        self.minsize(820, 580)
        self.q = queue.Queue()
        self.monitor = None
        self.path_thread = None
        self.path_targets = []
        self.scan_rows = []
        self.scan_cancel = None
        self.snap = None
        self.results = {}
        self.overall = UNKNOWN
        self.alerts = []
        self.last_popup = {}
        self.pinned = None            # (ifindex, ip, net_key)
        self.exiting = False

        self._style()
        self._build()
        from .tray import Tray
        self.tray = Tray(lambda: self.q.put(("tray_show",)),
                         lambda: self.q.put(("tray_toggle",)),
                         lambda: self.q.put(("tray_exit",)))
        self.tray.start()
        self.about_lbl.configure(text=self.about_lbl.cget("text") + "\nTray icon: " +
                                 ("on" if self.tray.ok else "not available"))
        self._set_icon()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(150, self.poll)
        self._render_banner()
        if self.settings.get("autostart_monitoring", True):
            self.after(300, self.start_monitor)

    # ------------------------------------------------------------------ UI
    def _style(self):
        st = ttk.Style(self)
        if sys.platform == "win32" and "vista" in st.theme_names():
            st.theme_use("vista")
        elif "clam" in st.theme_names():
            st.theme_use("clam")
        base = ("Segoe UI", 10) if sys.platform == "win32" else ("DejaVu Sans", 10)
        self.option_add("*Font", base)
        st.configure("Treeview", rowheight=24)
        st.configure("Big.TButton", font=(base[0], 11, "bold"), padding=(14, 6))
        st.configure("Card.TLabelframe.Label", font=(base[0], 10, "bold"))
        self.base_font = base

    def _set_icon(self):
        try:
            from PIL import ImageTk
            from .tray import make_image
            self._icon_img = ImageTk.PhotoImage(make_image("ok", 64))
            self.iconphoto(True, self._icon_img)
        except Exception:
            pass

    def _build(self):
        # Banner
        self.banner = tk.Frame(self, padx=16, pady=10)
        self.banner.pack(fill="x")
        left = tk.Frame(self.banner)
        left.pack(side="left", fill="x", expand=True)
        self.banner_left = left
        self.b_title = tk.Label(left, font=(self.base_font[0], 18, "bold"), anchor="w")
        self.b_title.pack(fill="x")
        self.b_sub = tk.Label(left, font=(self.base_font[0], 10), anchor="w", justify="left")
        self.b_sub.pack(fill="x")
        self.start_btn = ttk.Button(self.banner, text="Start", style="Big.TButton",
                                    command=self.toggle_monitor)
        self.start_btn.pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(6, 0))
        self._build_overview()
        self._build_alerts()
        self._build_devices()
        self._build_path()
        self._build_scan()
        self._build_settings()

        self.statusbar = ttk.Label(self, anchor="w", padding=(10, 3))
        self.statusbar.pack(fill="x")

    def _tree(self, parent, cols, widths, height=8):
        frame = ttk.Frame(parent)
        tv = ttk.Treeview(frame, columns=[c for c, _ in cols], show="headings",
                          height=height, selectmode="browse")
        for (c, text), w in zip(cols, widths):
            tv.heading(c, text=text)
            tv.column(c, width=w, anchor="w", stretch=(w > 200))
        sb = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for lvl, bg in ROW_BG.items():
            tv.tag_configure(lvl, background=bg)
        return frame, tv

    def _text(self, parent, height=6):
        t = ScrolledText(parent, height=height, wrap="word", relief="flat",
                         font=(self.base_font[0], 10), background="#fbfbfb")
        t.configure(state="disabled")
        return t

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # Overview ------------------------------------------------------------
    def _build_overview(self):
        tab = ttk.Frame(self.nb, padding=8)
        self.nb.add(tab, text="  Overview  ")
        card = ttk.LabelFrame(tab, text="Current connection", style="Card.TLabelframe",
                              padding=(10, 4))
        card.pack(fill="x")
        self.info_vars = {}
        fields = [("net", "Network"), ("sec", "Security"), ("router", "Router"),
                  ("maker", "Router maker"), ("myip", "Your IP"), ("dns", "DNS servers")]
        for i, (k, label) in enumerate(fields):
            r, c = divmod(i, 2)
            ttk.Label(card, text=label + ":", foreground="#555").grid(row=r, column=c * 2,
                                                                      sticky="w", padx=(0, 6))
            v = tk.StringVar(value="-")
            ttk.Label(card, textvariable=v).grid(row=r, column=c * 2 + 1, sticky="w",
                                                  padx=(0, 30))
            self.info_vars[k] = v

        ttk.Label(tab, text="Security checks  (click one to see what it means)",
                  font=(self.base_font[0], 10, "bold")).pack(anchor="w", pady=(8, 2))
        fr, self.check_tv = self._tree(tab, [("check", "Check"), ("result", "Result"),
                                             ("summary", "What we found")],
                                       [190, 90, 600], height=11)
        fr.pack(fill="both", expand=True)
        for key, name in CHECKS:
            self.check_tv.insert("", "end", iid=key, values=(name, "-", ""), tags=(UNKNOWN,))
        self.check_tv.bind("<<TreeviewSelect>>", lambda e: self._show_check())
        self.check_detail = self._text(tab, height=6)
        self.check_detail.pack(fill="x", pady=(6, 4))

        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Button(bar, text="Check now", command=lambda: self._monitor_cmd("recheck")).pack(side="left")
        ttk.Button(bar, text="Reset baseline", command=self.reset_baseline).pack(side="left", padx=4)
        ttk.Button(bar, text="Disconnect Wi-Fi", command=self.disconnect_wifi).pack(side="left", padx=4)
        self.pin_btn = ttk.Button(bar, text="Pin router address", command=self.toggle_pin)
        self.pin_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="Save report", command=self.save_report).pack(side="right")

    def _show_check(self):
        sel = self.check_tv.selection()
        if not sel:
            return
        r = self.results.get(sel[0])
        if not r:
            self._set_text(self.check_detail, "No result yet.")
            return
        txt = f"{r['name']}: {WORDS[r['status']]}\n{r['summary']}\n"
        if r["details"]:
            txt += "\n" + r["details"] + "\n"
        if r["action"]:
            txt += "\nWhat to do: " + r["action"]
        self._set_text(self.check_detail, txt)

    # Alerts --------------------------------------------------------------
    def _build_alerts(self):
        tab = ttk.Frame(self.nb, padding=8)
        self.nb.add(tab, text="  Alerts  ")
        self.alerts_tab = tab
        fr, self.alert_tv = self._tree(tab, [("time", "Time"), ("level", "Level"),
                                             ("title", "Event"), ("msg", "Details")],
                                       [80, 80, 200, 560], height=14)
        fr.pack(fill="both", expand=True)
        self.alert_tv.bind("<<TreeviewSelect>>", lambda e: self._show_alert())
        self.alert_detail = self._text(tab, height=7)
        self.alert_detail.pack(fill="x", pady=6)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Button(bar, text="Clear list", command=self.clear_alerts).pack(side="left")
        ttk.Button(bar, text="Open log folder",
                   command=lambda: open_folder(os.path.join(storage.data_dir(), "logs"))
                   ).pack(side="left", padx=4)

    def _show_alert(self):
        sel = self.alert_tv.selection()
        if not sel:
            return
        e = self.alerts[int(sel[0])]
        txt = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['time']))}  " \
              f"{WORDS.get(e['level'], e['level'])}: {e['title']}\n{e['message']}\n"
        if e.get("details"):
            txt += "\n" + e["details"] + "\n"
        if e.get("action"):
            txt += "\nWhat to do: " + e["action"]
        self._set_text(self.alert_detail, txt)

    def clear_alerts(self):
        self.alerts.clear()
        self.alert_tv.delete(*self.alert_tv.get_children())
        self._set_text(self.alert_detail, "")
        self.nb.tab(self.alerts_tab, text="  Alerts  ")

    # Devices -------------------------------------------------------------
    def _build_devices(self):
        tab = ttk.Frame(self.nb, padding=8)
        self.nb.add(tab, text="  Devices  ")
        ttk.Label(tab, text="Devices your computer has talked to on this network "
                            "(its address table). Updated every check.",
                  foreground="#555").pack(anchor="w", pady=(0, 4))
        fr, self.dev_tv = self._tree(tab, [("ip", "IP address"), ("mac", "Hardware (MAC)"),
                                           ("maker", "Maker"), ("note", "Notes")],
                                     [260, 150, 260, 250], height=20)
        fr.pack(fill="both", expand=True)

    def _render_devices(self):
        tv = self.dev_tv
        tv.delete(*tv.get_children())
        s = self.snap or {}
        gw, gm = s.get("gateway_ip"), s.get("gateway_mac")
        n4 = s.get("neighbors4", {})
        counts = {}
        for m in n4.values():
            counts[m] = counts.get(m, 0) + 1
        import ipaddress
        for ip in sorted(n4, key=lambda x: int(ipaddress.IPv4Address(x))):
            mac = n4[ip]
            notes, lvl = [], OK
            if ip == gw:
                notes.append("Router")
                if self.results.get("gateway", {}).get("status") == ALERT:
                    notes.append("MAC CHANGED")
                    lvl = ALERT
            elif mac == gm:
                notes.append("SAME MAC AS ROUTER")
                lvl = ALERT
            elif counts[mac] > 1:
                notes.append("Shares a MAC")
                lvl = WARN
            if ip in s.get("neighbors4_static", set()):
                notes.append("Pinned (static)")
            cat = oui.category(mac)
            if cat in ("randomized", "virtual", "sbc", "attack_tool"):
                notes.append({"randomized": "Randomized MAC", "virtual": "Virtual machine",
                              "sbc": "Raspberry Pi", "attack_tool": "Hacking hardware"}[cat])
            tv.insert("", "end", values=(ip, mac, oui.vendor(mac) or "", ", ".join(notes)),
                      tags=(lvl if lvl != OK else INFO,))
        for n in s.get("neighbors6", []):
            note = "IPv6 router" if n.get("is_router") else ""
            tv.insert("", "end", values=(n["ip"], n["mac"], oui.vendor(n["mac"]) or "", note),
                      tags=(INFO,))

    # Path monitor ----------------------------------------------------------
    def _build_path(self):
        tab = ttk.Frame(self.nb, padding=8)
        self.nb.add(tab, text="  Path Monitor  ")
        ttk.Label(tab, wraplength=900, foreground="#555", justify="left",
                  text="Repeatedly traces the route to other devices (for example, a server "
                       "across campus). It learns the normal path over the first 3 runs, then "
                       "alerts on new devices in the path, a changed route, latency jumps, or "
                       "the connection going down. Limit: a device that silently bridges "
                       "traffic (no routing) won't appear as a hop.").pack(anchor="w")
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Targets (IPs or names, comma-separated):").pack(side="left")
        self.path_entry = ttk.Entry(row, width=40)
        self.path_entry.insert(0, self.settings.get("path_targets", ""))
        self.path_entry.pack(side="left", padx=6)
        ttk.Label(row, text="Every").pack(side="left")
        self.path_int = tk.StringVar(value=str(self.settings.get("path_interval", 60)))
        ttk.Spinbox(row, from_=10, to=3600, width=6, textvariable=self.path_int).pack(side="left", padx=4)
        ttk.Label(row, text="sec").pack(side="left")
        self.path_btn = ttk.Button(row, text="Start", command=self.toggle_path)
        self.path_btn.pack(side="left", padx=8)
        ttk.Button(row, text="Accept current path", command=self.accept_path).pack(side="left")

        row2 = ttk.Frame(tab)
        row2.pack(fill="x")
        ttk.Label(row2, text="Show:").pack(side="left")
        self.path_sel = ttk.Combobox(row2, state="readonly", width=30)
        self.path_sel.pack(side="left", padx=6)
        self.path_sel.bind("<<ComboboxSelected>>", lambda e: self._render_path())
        self.path_status = tk.Label(row2, anchor="w", font=(self.base_font[0], 10, "bold"))
        self.path_status.pack(side="left", fill="x", expand=True, padx=8)
        fr, self.path_tv = self._tree(tab, [("hop", "Hop"), ("ip", "IP address"),
                                            ("name", "Name"), ("rtt", "Time"),
                                            ("mac", "MAC (local only)"), ("maker", "Maker"),
                                            ("note", "Note")],
                                      [45, 130, 230, 70, 140, 170, 150], height=14)
        fr.pack(fill="both", expand=True, pady=6)

    def toggle_path(self):
        if self.path_thread and self.path_thread.is_alive():
            self.path_thread.stop_ev.set()
            self.path_btn.configure(text="Stopping...", state="disabled")
            return
        hosts = [h.strip() for h in self.path_entry.get().split(",") if h.strip()]
        if not hosts:
            messagebox.showinfo(APP_NAME, "Enter at least one target IP or hostname.")
            return
        try:
            interval = max(10, int(float(self.path_int.get())))
        except ValueError:
            interval = 60
        self.settings["path_targets"] = ", ".join(hosts)
        self.settings["path_interval"] = interval
        storage.save_settings(self.settings)
        old = {t.host: t for t in self.path_targets}
        self.path_targets = [old.get(h) or pathmon.Target(h) for h in hosts]
        self.path_sel["values"] = hosts
        if self.path_sel.get() not in hosts:
            self.path_sel.set(hosts[0])
        self.path_thread = PathThread(self.q, self.path_targets, interval)
        self.path_thread.start()
        self.path_btn.configure(text="Stop")
        self._render_path()

    def accept_path(self):
        t = self._current_target()
        if t and t.hops:
            t.accept_current()
            self._render_path()

    def _current_target(self):
        h = self.path_sel.get()
        return next((t for t in self.path_targets if t.host == h), None)

    def _render_path(self):
        t = self._current_target()
        tv = self.path_tv
        tv.delete(*tv.get_children())
        if not t:
            self.path_status.configure(text="")
            return
        colors = {OK: "#1e7e34", WARN: "#a07800", ALERT: "#c82333", INFO: "#333"}
        self.path_status.configure(text=f"{WORDS.get(t.status, t.status)}: {t.summary}",
                                   fg=colors.get(t.status, "#333"))
        learning = t.runs <= pathmon.LEARN_RUNS
        for h in t.hops:
            note, lvl = "", INFO
            if h["ip"] is None:
                vals = (h["ttl"], "*", "(no reply)", "", "", "", "")
            else:
                if h["reached"]:
                    note = "Destination"
                elif self.snap and h["ip"] == self.snap.get("gateway_ip"):
                    note = "Your router"
                if not learning and h["ip"] not in t.known and h["ip"] != t.ip:
                    note, lvl = "NEW - not in normal path", ALERT
                rtt = f"{h['rtt']} ms" if h["rtt"] is not None else ""
                vals = (h["ttl"], h["ip"], h.get("name", ""), rtt, h.get("mac") or "",
                        h.get("vendor") or "", note)
            tv.insert("", "end", values=vals, tags=(lvl,))

    # Scan ------------------------------------------------------------------
    def _build_scan(self):
        tab = ttk.Frame(self.nb, padding=8)
        self.nb.add(tab, text="  Network Scan  ")
        ttk.Label(tab, wraplength=900, foreground="#555", justify="left",
                  text="Finds devices in an IP range and flags suspicious ones (duplicate "
                       "hardware addresses, randomized MACs, virtual machines, known hacking "
                       "hardware). Only scan networks you are responsible for. Most public "
                       "Wi-Fi blocks device-to-device traffic, so few devices will show there.").pack(anchor="w")
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Range:").pack(side="left")
        self.scan_entry = ttk.Entry(row, width=34)
        self.scan_entry.insert(0, self.settings.get("scan_range", ""))
        self.scan_entry.pack(side="left", padx=6)
        ttk.Button(row, text="Use my subnet", command=self.use_my_subnet).pack(side="left")
        self.scan_btn = ttk.Button(row, text="Scan", command=self.toggle_scan)
        self.scan_btn.pack(side="left", padx=8)
        ttk.Button(row, text="Export CSV", command=self.export_scan).pack(side="right")
        ttk.Label(tab, text="Examples: 192.168.1.0/24   10.20.30.1-10.20.30.120   "
                            "10.20.30.1-120   (max 1024 addresses)",
                  foreground="#777").pack(anchor="w")
        prow = ttk.Frame(tab)
        prow.pack(fill="x", pady=4)
        self.scan_prog = ttk.Progressbar(prow, mode="determinate")
        self.scan_prog.pack(side="left", fill="x", expand=True)
        self.scan_lbl = ttk.Label(prow, text="", width=40)
        self.scan_lbl.pack(side="left", padx=8)
        fr, self.scan_tv = self._tree(tab, [("ip", "IP address"), ("name", "Name"),
                                            ("mac", "Hardware (MAC)"), ("maker", "Maker"),
                                            ("ping", "Ping"), ("flags", "Notes")],
                                      [120, 200, 140, 200, 60, 260], height=16)
        fr.pack(fill="both", expand=True)

    def use_my_subnet(self):
        net = sysinfo.local_subnet(self.snap or {})
        if not net:
            messagebox.showinfo(APP_NAME, "Couldn't detect your subnet yet. Start monitoring "
                                          "first or type a range.")
            return
        self.scan_entry.delete(0, "end")
        self.scan_entry.insert(0, str(net))

    def toggle_scan(self):
        if self.scan_cancel is not None:
            self.scan_cancel.set()
            self.scan_btn.configure(text="Cancelling...", state="disabled")
            return
        spec = self.scan_entry.get().strip()
        ips, err = scanner.parse_targets(spec, sysinfo.local_subnet(self.snap or {}))
        if err:
            messagebox.showerror(APP_NAME, err)
            return
        self.settings["scan_range"] = spec
        storage.save_settings(self.settings)
        self.scan_cancel = threading.Event()
        self.scan_btn.configure(text="Cancel")
        self.scan_prog.configure(maximum=len(ips), value=0)
        self.scan_lbl.configure(text=f"Scanning {len(ips)} addresses...")
        s = self.snap or {}
        my_ip = ((s.get("adapter") or {}).get("ipv4") or [None])[0]
        cancel = self.scan_cancel

        def work():
            try:
                rows = scanner.sweep(ips, lambda d, t: self.q.put(("scan_progress", d, t)),
                                     cancel, my_ip, s.get("gateway_ip"))
                self.q.put(("scan_done", rows, cancel.is_set()))
            except Exception as e:
                self.q.put(("scan_done", [], False))
                self.q.put(("error", f"Scan error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _render_scan(self):
        tv = self.scan_tv
        tv.delete(*tv.get_children())
        for r in self.scan_rows:
            tv.insert("", "end", values=(r["ip"], r["name"], r["mac"] or "-", r["vendor"] or "",
                                         f"{r['rtt']} ms" if r["rtt"] is not None else "no",
                                         "; ".join(r["flags"])),
                      tags=(r["level"] if r["level"] != OK else INFO,))

    def export_scan(self):
        if not self.scan_rows:
            messagebox.showinfo(APP_NAME, "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            initialdir=storage.reports_dir(), defaultextension=".csv",
            initialfile=time.strftime("scan-%Y%m%d-%H%M%S.csv"), filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Name", "MAC", "Maker", "Ping ms", "Notes"])
            for r in self.scan_rows:
                w.writerow([r["ip"], r["name"], r["mac"], r["vendor"], r["rtt"],
                            "; ".join(r["flags"])])

    # Settings --------------------------------------------------------------
    def _build_settings(self):
        tab = ttk.Frame(self.nb, padding=12)
        self.nb.add(tab, text="  Settings  ")
        self.set_vars = {}
        ttk.Label(tab, text="Checks", font=(self.base_font[0], 10, "bold")).grid(
            row=0, column=0, sticky="w")
        opts = [("check_wifi", "Wi-Fi checks (fake/evil-twin hotspots)"),
                ("check_first_hop", "Traffic route check (is anything between me and the router?)"),
                ("check_ipv6", "IPv6 checks (rogue IPv6 router / mitm6)"),
                ("check_web", "Internet checks (sign-in page, HTTPS interception, DNS)"),
                ("popups", "Pop-up window on alerts"),
                ("sound", "Sound on alerts"),
                ("minimize_to_tray", "Closing the window keeps ARP Watch running in the tray"),
                ("autostart_monitoring", "Start monitoring when ARP Watch opens")]
        for i, (k, text) in enumerate(opts, start=1):
            v = tk.BooleanVar(value=bool(self.settings.get(k, True)))
            ttk.Checkbutton(tab, text=text, variable=v, command=self._save_settings).grid(
                row=i, column=0, columnspan=3, sticky="w", pady=1)
            self.set_vars[k] = v
        r = len(opts) + 1
        ttk.Label(tab, text="Check every (seconds):").grid(row=r, column=0, sticky="w", pady=(8, 0))
        self.int_var = tk.StringVar(value=str(self.settings.get("interval", 5)))
        sp = ttk.Spinbox(tab, from_=2, to=600, width=6, textvariable=self.int_var,
                         command=self._save_settings)
        sp.grid(row=r, column=1, sticky="w", pady=(8, 0))
        sp.bind("<FocusOut>", lambda e: self._save_settings())

        r += 1
        ttk.Separator(tab).grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
        r += 1
        portable = storage.is_portable()
        info = (f"Version {__version__}\n"
                f"Data folder: {storage.data_dir()}\n"
                f"Portable mode: {'ON (data saved next to the program)' if portable else 'off'}\n"
                f"Running as administrator: {'yes' if winapi.is_admin() else 'no (only needed for Pin router address)'}")
        self.about_lbl = ttk.Label(tab, text=info, justify="left")
        self.about_lbl.grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1
        bar = ttk.Frame(tab)
        bar.grid(row=r, column=0, columnspan=3, sticky="w", pady=8)
        ttk.Button(bar, text="Open data folder", command=lambda: open_folder(storage.data_dir())).pack(side="left")
        ttk.Button(bar, text="Run diagnostics", command=self.run_diagnostics).pack(side="left", padx=6)
        ttk.Button(bar, text="Forget remembered networks", command=self.forget_networks).pack(side="left")

    def _save_settings(self):
        for k, v in self.set_vars.items():
            self.settings[k] = bool(v.get())
        try:
            self.settings["interval"] = max(2, int(float(self.int_var.get())))
        except ValueError:
            pass
        storage.save_settings(self.settings)
        if self.monitor:
            self.monitor.settings.update(self.settings)
            self._monitor_cmd("recheck")

    def forget_networks(self):
        if messagebox.askyesno(APP_NAME, "Forget every network ARP Watch has remembered?"):
            self.known.clear()
            storage.save_known_networks(self.known)
            self.reset_baseline()

    def run_diagnostics(self):
        win = tk.Toplevel(self)
        win.title("Diagnostics")
        win.geometry("820x560")
        txt = self._text(win, height=30)
        txt.configure(font=("Consolas", 9))
        txt.pack(fill="both", expand=True)
        self._set_text(txt, "Running diagnostics (takes ~15 seconds)...")

        def work():
            out = actions.diagnostics()
            path = os.path.join(storage.reports_dir(),
                                time.strftime("diagnostics-%Y%m%d-%H%M%S.txt"))
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(out)
                out += f"\n\nSaved to {path}"
            except OSError:
                pass
            self.q.put(("diag", txt, out))
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ actions
    def toggle_monitor(self):
        if self.monitor and self.monitor.is_alive():
            self.monitor.stop()
            self.start_btn.configure(text="Stopping...", state="disabled")
        else:
            self.start_monitor()

    def start_monitor(self):
        if self.monitor and self.monitor.is_alive():
            return
        self.monitor = MonitorThread(self.q, self.settings, self.known)
        self.monitor.start()
        self.start_btn.configure(text="Stop", state="normal")
        self.b_title.configure(text="Checking your network...")
        self.statusbar.configure(text="Starting...")

    def _monitor_cmd(self, c):
        if self.monitor and self.monitor.is_alive():
            self.monitor.command(c)

    def reset_baseline(self):
        if not (self.monitor and self.monitor.is_alive()):
            return
        if self.overall == ALERT and not messagebox.askyesno(
                APP_NAME, "There is an active ALERT. Resetting accepts the current state as "
                          "normal.\n\nOnly do this if you know why it changed. Reset?"):
            return
        self._monitor_cmd("reset")

    def disconnect_wifi(self):
        s = self.snap or {}
        if not s.get("wifi"):
            messagebox.showinfo(APP_NAME, "You're not connected to Wi-Fi.")
            return
        if messagebox.askyesno(APP_NAME, f"Disconnect from '{s['wifi'].get('ssid')}' now?"):
            ok, out = actions.disconnect_wifi(s["wifi"]["name"])
            if not ok:
                messagebox.showwarning(APP_NAME, f"Windows said:\n{out or 'no response'}")

    def toggle_pin(self):
        s = self.snap or {}
        if self.pinned:
            ifi, ip, _ = self.pinned
            actions.unpin_gateway(ifi, ip)
            self.pinned = None
            self.pin_btn.configure(text="Pin router address")
            return
        gw, gm, ifi = s.get("gateway_ip"), s.get("gateway_mac"), s.get("ifindex")
        if not (gw and gm and ifi):
            messagebox.showinfo(APP_NAME, "Router address not known yet.")
            return
        if self.overall == ALERT:
            messagebox.showwarning(APP_NAME, "There's an active alert, so the current router "
                                             "address may be the attacker's. Not pinning.")
            return
        if not messagebox.askyesno(
                APP_NAME,
                f"Pin router {gw} to {gm} ({oui.vendor(gm) or 'unknown maker'})?\n\n"
                "This tells Windows to ignore anyone else claiming to be the router, which "
                "blocks ARP spoofing. It needs administrator rights (Windows will ask), lasts "
                "until you unpin or restart, and ARP Watch will offer to remove it when you "
                "leave this network."):
            return
        if not actions.pin_gateway(ifi, gw, gm):
            messagebox.showwarning(APP_NAME, "Couldn't get administrator rights.")
            return

        def verify():
            if actions.is_pinned(ifi, gw):
                self.pinned = (ifi, gw, s.get("net_key"))
                self.pin_btn.configure(text="Unpin router address")
                messagebox.showinfo(APP_NAME, "Router address pinned.")
            else:
                messagebox.showwarning(APP_NAME, "The pin didn't take effect (the admin prompt "
                                                 "may have been declined).")
        self.after(2500, verify)

    def save_report(self):
        text = actions.build_report(self.snap, self.results, self.overall, self.alerts,
                                    self.path_targets, self.scan_rows)
        path = actions.save_report(text)
        if messagebox.askyesno(APP_NAME, f"Report saved:\n{path}\n\nOpen it now?"):
            open_folder(path)

    # ------------------------------------------------------------ events
    def handle_events(self, events):
        for e in events:
            storage.log_line(f"[{e['level'].upper()}] {e['title']}: {e['message']}"
                             + (" | " + e["details"].replace("\n", " | ") if e.get("details") else ""))
            self.alerts.append(e)
            idx = len(self.alerts) - 1
            self.alert_tv.insert("", 0, iid=str(idx),
                                 values=(fmt_time(e["time"]), WORDS.get(e["level"], e["level"]),
                                         e["title"], e["message"]),
                                 tags=(e["level"],))
            if e["level"] in (WARN, ALERT):
                self.tray.notify(f"{WORDS[e['level']]}: {e['title']}", e["message"])
            if e["level"] == ALERT:
                if self.settings.get("sound", True):
                    winapi.beep()
                key = e["title"]
                if self.settings.get("popups", True) and \
                        time.time() - self.last_popup.get(key, 0) > POPUP_COOLDOWN:
                    self.last_popup[key] = time.time()
                    msg = f"{e['message']}\n\n{e.get('details', '')}\n\nWhat to do: {e.get('action', '')}"
                    threading.Thread(target=winapi.message_box,
                                     args=(f"{APP_NAME}: {e['title']}", msg[:1500]),
                                     daemon=True).start()
        n = sum(1 for e in self.alerts if e["level"] in (WARN, ALERT))
        self.nb.tab(self.alerts_tab, text=f"  Alerts ({n})  " if n else "  Alerts  ")

    def _render_banner(self):
        level = self.overall if (self.monitor and self.monitor.is_alive()) else UNKNOWN
        bg, fg, title, sub = BANNER[level]
        if level == UNKNOWN and self.monitor and self.monitor.is_alive():
            title, sub = "Checking your network...", "This takes a few seconds."
        if self.snap is not None and not self.snap.get("net_key") and self.monitor:
            title, sub = "Not connected", "Waiting for a network connection."
        bad = [r for r in self.results.values() if r["status"] == level and level in (WARN, ALERT)]
        if bad:
            sub = f"{bad[0]['name']}: {bad[0]['summary']}" + \
                  (f"  (+{len(bad) - 1} more)" if len(bad) > 1 else "") + "\n" + sub
        for w in (self.banner, self.banner_left, self.b_title, self.b_sub):
            w.configure(bg=bg)
        self.b_title.configure(text=title, fg=fg)
        self.b_sub.configure(text=sub, fg=fg)
        tip = f"ARP Watch - {title}"
        if self.snap and self.snap.get("net_name"):
            tip += f" ({self.snap['net_name']})"
        self.tray.set_status(level, tip)

    def _render_state(self):
        s = self.snap or {}
        a = s.get("adapter") or {}
        w = s.get("wifi") or {}
        iv = self.info_vars
        iv["net"].set((s.get("net_name") or "Not connected") +
                      (f"   (VPN active: {s['vpn']})" if s.get("vpn") else ""))
        iv["sec"].set(w.get("auth") + (" (OPEN - no password)" if sysinfo.is_open_auth(w.get("auth")) else "")
                      if w else ("Wired" if s.get("net_key") else "-"))
        iv["router"].set(f"{s.get('gateway_ip') or '-'}   {s.get('gateway_mac') or ''}")
        iv["maker"].set(oui.vendor(s.get("gateway_mac")) or "-")
        iv["myip"].set(", ".join(a.get("ipv4", [])) or "-")
        iv["dns"].set(", ".join(a.get("dns4", []) + a.get("dns6", [])) or "-")
        for key, _ in CHECKS:
            r = self.results.get(key)
            if r:
                self.check_tv.item(key, values=(r["name"], WORDS[r["status"]], r["summary"]),
                                   tags=(r["status"],))
        self._show_check()
        self._render_devices()
        self._render_banner()
        # pinned router: offer to unpin after leaving that network
        if self.pinned and s.get("net_key") and s.get("net_key") != self.pinned[2]:
            ifi, ip, _ = self.pinned
            self.pinned = None
            self.pin_btn.configure(text="Pin router address")
            if messagebox.askyesno(APP_NAME, f"You left the network where router {ip} was "
                                             f"pinned. Remove the pin now? (Recommended - it "
                                             f"can break other networks.)"):
                actions.unpin_gateway(ifi, ip)

    # ------------------------------------------------------------ queue
    def poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "state":
                    _, self.snap, self.results, self.overall, events = msg
                    self._render_state()
                    self.handle_events(events)
                    self.statusbar.configure(
                        text=f"Monitoring  |  last check {fmt_time(time.time())}  |  "
                             f"every {self.settings.get('interval', 5)}s  |  "
                             f"data: {storage.data_dir()}")
                elif kind == "stopped":
                    self.start_btn.configure(text="Start", state="normal")
                    self.statusbar.configure(text="Monitoring stopped.")
                    self._render_banner()
                elif kind == "error":
                    self.statusbar.configure(text=msg[1])
                    storage.log_line("[ERROR] " + msg[1])
                elif kind == "path":
                    self.handle_events(msg[1])
                    self._render_path()
                elif kind == "path_running":
                    if self.path_sel.get() == msg[1]:
                        self.path_status.configure(text=f"Tracing route to {msg[1]}...",
                                                   fg="#333")
                elif kind == "path_stopped":
                    self.path_btn.configure(text="Start", state="normal")
                elif kind == "scan_progress":
                    self.scan_prog.configure(value=msg[1])
                    self.scan_lbl.configure(text=f"{msg[1]} / {msg[2]} addresses")
                elif kind == "scan_done":
                    rows, cancelled = msg[1], msg[2]
                    self.scan_cancel = None
                    self.scan_btn.configure(text="Scan", state="normal")
                    if not cancelled:
                        self.scan_rows = rows
                        self._render_scan()
                        flagged = sum(1 for r in rows if r["level"] != OK)
                        self.scan_lbl.configure(
                            text=f"Found {len(rows)} devices" +
                                 (f", {flagged} flagged" if flagged else ""))
                    else:
                        self.scan_lbl.configure(text="Scan cancelled.")
                elif kind == "diag":
                    try:
                        self._set_text(msg[1], msg[2])
                    except tk.TclError:
                        pass
                elif kind == "tray_show":
                    self.show_window()
                elif kind == "tray_toggle":
                    self.toggle_monitor()
                elif kind == "tray_exit":
                    self.exit_app()
        except queue.Empty:
            pass
        if not self.exiting:
            self.after(200, self.poll)

    # ------------------------------------------------------------ window
    def show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def on_close(self):
        if self.tray.ok and self.settings.get("minimize_to_tray", True):
            self.withdraw()
            if not getattr(self, "_told_tray", False):
                self.tray.notify(APP_NAME, "Still protecting you in the background. "
                                           "Right-click the tray icon to exit.")
                self._told_tray = True
            return
        if self.monitor and self.monitor.is_alive() and not messagebox.askyesno(
                APP_NAME, "Monitoring is running. Stop and exit?"):
            return
        self.exit_app()

    def exit_app(self):
        if self.pinned:
            ifi, ip, _ = self.pinned
            if messagebox.askyesno(APP_NAME, f"Remove the router pin for {ip} before exiting? "
                                             f"(Recommended)"):
                actions.unpin_gateway(ifi, ip)
        self.exiting = True
        if self.monitor:
            self.monitor.stop()
        if self.path_thread:
            self.path_thread.stop_ev.set()
        if self.scan_cancel:
            self.scan_cancel.set()
        try:
            storage.save_known_networks(self.known)
        except OSError:
            pass
        self.tray.stop()
        self.destroy()


def main():
    if "--diagnostics" in sys.argv:
        out = actions.diagnostics()
        path = os.path.join(storage.reports_dir(), "diagnostics.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        try:
            print(out)
        except Exception:
            pass
        return
    App().mainloop()
    os._exit(0)   # don't let a stuck tray/helper thread keep the process alive
