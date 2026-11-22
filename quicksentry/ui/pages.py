"""The pages shown in the main window's content area."""
from __future__ import annotations

import ipaddress
import time

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QBrush, QPainter
from PySide6.QtWidgets import (QComboBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QProgressBar,
                               QSpinBox, QSplitter, QTextEdit, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

from .. import __version__, oui, pathmon, storage, sysinfo
from ..engine import ALERT, CHECKS, INFO, OK, WARN
from ..guard import netwatch
from ..guard.hardware import DEFAULT_POLICIES, POLICIES, POLICY_HELP
from ..guard.win32dev import CATEGORY_LABELS
from .theme import AMBER, DIM, LEVEL, LIME, MAGENTA, RED, TEXT, VIOLET, col, mono, tech
from .widgets import GelButton, GelToggle, HudPanel, LedOrb, StatusPod, neon_text

BANNER = {
    OK: ("NO SIGNS OF ATTACK", "Network, ports and hardware all look clean."),
    INFO: ("NO SIGNS OF ATTACK", "Network, ports and hardware all look clean."),
    WARN: ("SOMETHING LOOKS UNUSUAL", "Review the yellow items. Avoid logins and banking unless you're on a VPN."),
    ALERT: ("POSSIBLE ATTACK DETECTED", "Stop sensitive activity, then review the red items."),
    "unknown": ("STANDING BY", "Starting checks…"),
}


def fmt_time(t):
    return time.strftime("%H:%M:%S", time.localtime(t))


def tree(cols, widths, parent=None):
    t = QTreeWidget(parent)
    t.setColumnCount(len(cols))
    t.setHeaderLabels([c.upper() for c in cols])
    t.setRootIsDecorated(False)
    t.setAlternatingRowColors(True)
    t.setUniformRowHeights(True)
    t.setSelectionMode(QTreeWidget.SingleSelection)
    for i, w in enumerate(widths):
        t.setColumnWidth(i, w)
    t.header().setStretchLastSection(True)
    return t


def row(values, level=None, data=None):
    it = QTreeWidgetItem([str(v) for v in values])
    if level:
        c = col(LEVEL.get(level, LEVEL["info"])[0])
        for i in range(len(values)):
            it.setForeground(i, QBrush(c if level not in ("ok", "info") or i == 0 else col(TEXT)))
    if data is not None:
        it.setData(0, Qt.UserRole, data)
    return it


def panel(title, accent=VIOLET):
    p = HudPanel(title, accent=accent)
    lay = QVBoxLayout(p)
    lay.setContentsMargins(14, 36 if title else 12, 14, 12)
    lay.setSpacing(8)
    return p, lay


def hbox(*widgets, stretch_end=True):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(6)
    for x in widgets:
        if x == "stretch":
            h.addStretch(1)
        else:
            h.addWidget(x)
    if stretch_end and "stretch" not in widgets:
        h.addStretch(1)
    return w


def detail_box(h=110):
    t = QTextEdit()
    t.setReadOnly(True)
    t.setFixedHeight(h)
    return t


def dim(text):
    lab = QLabel(text)
    lab.setObjectName("dim")
    lab.setWordWrap(True)
    lab.setStyleSheet(f"color:{DIM}; font-family: Consolas; font-size: 8pt;")
    return lab


class Banner(QWidget):
    def __init__(self):
        super().__init__()
        self.level, self.title, self.sub = "unknown", *BANNER["unknown"]
        self.setFixedHeight(66)

    def set(self, level, title, sub):
        self.level, self.title, self.sub = level, title, sub
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = LEVEL.get(self.level, LEVEL["unknown"])[0]
        neon_text(p, QRectF(4, 0, self.width(), 34), self.title, tech(20), c)
        p.setFont(mono(9)); p.setPen(col(TEXT, 220))
        p.drawText(QRectF(6, 34, self.width() - 10, 32), Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, self.sub)


# =========================================================================== Overview
class OverviewPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(10)
        top, tl = panel("", LIME)
        self.banner = Banner()
        tl.addWidget(self.banner)
        pods = QWidget(); ph = QHBoxLayout(pods); ph.setContentsMargins(0, 0, 0, 0); ph.setSpacing(10)
        self.pod_net, self.pod_hw, self.pod_conn = StatusPod("Network"), StatusPod("Hardware"), StatusPod("Connections")
        for pod, page in ((self.pod_net, "Overview"), (self.pod_hw, "Hardware"), (self.pod_conn, "Connections")):
            pod.clicked.connect(lambda pg=page: app.goto(pg))
            ph.addWidget(pod)
        tl.addWidget(pods)
        v.addWidget(top)

        info, il = panel("Current connection")
        grid = QGridLayout(); grid.setHorizontalSpacing(18); grid.setVerticalSpacing(4)
        self.info = {}
        for i, (k, label) in enumerate([("net", "Network"), ("sec", "Security"), ("router", "Router"),
                                        ("maker", "Router maker"), ("myip", "Your IP"), ("dns", "DNS servers")]):
            r, c = divmod(i, 3)
            kl = QLabel(label.upper()); kl.setStyleSheet(f"color:{DIM}; font-family:Bahnschrift; font-size:8pt;")
            vl = QLabel("-"); vl.setStyleSheet(f"color:{LIME}; font-family:Consolas; font-size:9pt;")
            vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(kl, r * 2, c); grid.addWidget(vl, r * 2 + 1, c)
            self.info[k] = vl
        il.addLayout(grid)
        v.addWidget(info)

        chk, cl = panel("Security checks — click one for details")
        self.checks = tree(["Check", "Result", "What we found"], [200, 100, 500])
        for key, name in CHECKS:
            self.checks.addTopLevelItem(row([name, "…", ""], "unknown", key))
        self.checks.itemSelectionChanged.connect(self.show_check)
        cl.addWidget(self.checks, 1)
        self.detail = detail_box(100)
        cl.addWidget(self.detail)
        b = [GelButton("Check now", VIOLET), GelButton("Reset baseline", VIOLET), GelButton("Disconnect Wi-Fi", AMBER)]
        self.pin_btn = GelButton("Pin router address", VIOLET)
        rep = GelButton("Save report", "#2d6fd6")
        b[0].clicked.connect(lambda: app.net.command("recheck"))
        b[1].clicked.connect(app.reset_baseline)
        b[2].clicked.connect(app.disconnect_wifi)
        self.pin_btn.clicked.connect(app.toggle_pin)
        rep.clicked.connect(app.save_report)
        cl.addWidget(hbox(*b, self.pin_btn, "stretch", rep))
        v.addWidget(chk, 1)

    def show_check(self):
        it = self.checks.currentItem()
        if not it:
            return
        r = self.app.results.get(it.data(0, Qt.UserRole))
        if not r:
            self.detail.setPlainText("No result yet.")
            return
        txt = f"{r['name']}: {LEVEL[r['status']][1]}\n{r['summary']}\n"
        if r["details"]:
            txt += "\n" + r["details"] + "\n"
        if r["action"]:
            txt += "\nWhat to do: " + r["action"]
        self.detail.setPlainText(txt)

    def render(self):
        app, s = self.app, self.app.snap or {}
        a, w = s.get("adapter") or {}, s.get("wifi") or {}
        self.info["net"].setText((s.get("net_name") or "Not connected") + (f"  (VPN: {s['vpn']})" if s.get("vpn") else ""))
        self.info["sec"].setText((w.get("auth", "") + ("  OPEN — NO PASSWORD" if sysinfo.is_open_auth(w.get("auth")) else ""))
                                 if w else ("Wired" if s.get("net_key") else "-"))
        self.info["router"].setText(f"{s.get('gateway_ip') or '-'}  {s.get('gateway_mac') or ''}")
        self.info["maker"].setText(oui.vendor(s.get("gateway_mac")) or "-")
        self.info["myip"].setText(", ".join(a.get("ipv4", [])) or "-")
        self.info["dns"].setText(", ".join(a.get("dns4", []) + a.get("dns6", [])) or "-")
        for i in range(self.checks.topLevelItemCount()):
            it = self.checks.topLevelItem(i)
            r = app.results.get(it.data(0, Qt.UserRole))
            if r:
                new = row([r["name"], LEVEL[r["status"]][1], r["summary"]], r["status"], r["key"])
                for c in range(3):
                    it.setText(c, new.text(c)); it.setForeground(c, new.foreground(c))
        self.show_check()


# =========================================================================== Alerts
class AlertsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0)
        p, l = panel("Event log — network, hardware, connections, path monitor", MAGENTA)
        self.tv = tree(["Time", "Source", "Level", "Event", "Details"], [80, 110, 80, 330, 400])
        self.tv.itemSelectionChanged.connect(self.show)
        l.addWidget(self.tv, 1)
        self.detail = detail_box(130)
        l.addWidget(self.detail)
        c = GelButton("Clear list", VIOLET)
        o = GelButton("Open log folder", VIOLET)
        c.clicked.connect(self.clear)
        o.clicked.connect(lambda: app.open_folder(storage.data_dir() + "/logs"))
        l.addWidget(hbox(c, o))
        v.addWidget(p)

    def add(self, e):
        it = row([fmt_time(e["time"]), e.get("source", "network").upper(), LEVEL.get(e["level"], LEVEL["info"])[1],
                  e["title"], e["message"]], e["level"], e)
        self.tv.insertTopLevelItem(0, it)
        while self.tv.topLevelItemCount() > 1000:
            self.tv.takeTopLevelItem(self.tv.topLevelItemCount() - 1)

    def show(self):
        it = self.tv.currentItem()
        if not it:
            return
        e = it.data(0, Qt.UserRole)
        txt = (f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['time']))}  [{e.get('source', '')}] "
               f"{LEVEL.get(e['level'], LEVEL['info'])[1]}: {e['title']}\n{e['message']}\n")
        if e.get("details"):
            txt += "\n" + e["details"] + "\n"
        if e.get("action"):
            txt += "\nWhat to do: " + e["action"]
        self.detail.setPlainText(txt)

    def clear(self):
        self.tv.clear()
        self.detail.clear()
        self.app.alert_count = 0
        self.app.refresh_status()


# =========================================================================== Hardware
class HardwarePage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app, hw = app, app.hw
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(10)
        top = QWidget(); th = QHBoxLayout(top); th.setContentsMargins(0, 0, 0, 0); th.setSpacing(10)

        sh, sl = panel("Shields", LIME)
        self.toggles = {
            "guard_speed_trap": GelToggle("Speed trap", "freeze on robot-speed typing"),
            "guard_defender": GelToggle("Defender scan", "MS Defender checks new drives"),
            "guard_autoplay": GelToggle("Kill AutoPlay", "never auto-open removable media"),
            "guard_strict": GelToggle("Strict mode", "no auto drive letters (mountvol /N)"),
        }
        for k, t in self.toggles.items():
            t.setChecked(bool(app.settings.get(k, k != "guard_strict")))
            t.toggled.connect(lambda on, key=k: hw.set_option(key, on))
            sl.addWidget(t)
        self.dma_led = LedOrb(DIM)
        self.dma_lab = QLabel("Kernel DMA Protection: checking…")
        self.dma_lab.setStyleSheet("font-family: Consolas; font-size: 8pt;")
        sl.addWidget(hbox(self.dma_led, self.dma_lab))
        scan = GelButton("Scan plugged-in drives", "#2d6fd6")
        scan.clicked.connect(hw.scan_connected)
        sl.addWidget(scan)
        sl.addStretch(1)
        sh.setFixedWidth(330)
        th.addWidget(sh)

        pol, pl = panel("Device rules — what happens when something new is plugged in")
        grid = QGridLayout(); grid.setHorizontalSpacing(10); grid.setVerticalSpacing(5)
        self.combos = {}
        cats = ["keyboard", "storage", "network", "phone", "thunderbolt", "bluetooth", "serial", "usb_other",
                "mouse", "camera", "audio", "display", "printer", "smartcard"]
        for i, cat in enumerate(cats):
            r, c = i % 7, (i // 7) * 2
            lab = QLabel(CATEGORY_LABELS[cat].upper())
            lab.setStyleSheet(f"font-family: Bahnschrift; font-size: 8.5pt; color:{TEXT};")
            lab.setToolTip(POLICY_HELP.get(cat, ""))
            cb = QComboBox()
            cb.addItems(POLICIES)
            cb.setCurrentText(hw.policy(cat))
            cb.setToolTip(POLICY_HELP.get(cat, "") + "\n\nlog = allow quietly · alert = allow + warn · "
                          "ask = hold until you approve · block = disable")
            cb.currentTextChanged.connect(lambda val, k=cat: hw.set_policy(k, val))
            grid.addWidget(lab, r, c); grid.addWidget(cb, r, c + 1)
            self.combos[cat] = cb
        pl.addLayout(grid)
        pl.addWidget(dim("ASK on a keyboard = freeze typing until a human types a code.  ASK on storage = "
                         "quarantine with no drive letter + scan.  ASK on anything else = disabled until you click Allow."))
        th.addWidget(pol, 1)
        v.addWidget(top)

        split = QSplitter(Qt.Vertical)
        dp, dl = panel("Drives", LIME)
        self.drives = tree(["Drive", "Bus", "Status", "Files", "Defender", "Findings"], [260, 80, 110, 70, 100, 300])
        self.drives.itemSelectionChanged.connect(self._drive_sel)
        dl.addWidget(self.drives, 1)
        self.b_release, self.b_rescan, self.b_forget = (GelButton("Release", "#3f9d00"), GelButton("Rescan", VIOLET),
                                                        GelButton("Forget", "#56607f"))
        self.b_release.clicked.connect(lambda: self._drive_act(hw.release))
        self.b_rescan.clicked.connect(lambda: self._drive_act(hw.rescan))
        self.b_forget.clicked.connect(self._forget)
        dl.addWidget(hbox(self.b_release, self.b_rescan, self.b_forget))
        split.addWidget(dp)

        lp, ll = panel("Device log", VIOLET)
        self.devlog = tree(["Time", "Device", "Type", "Bus", "ID", "Action"], [80, 270, 150, 110, 90, 200])
        ll.addWidget(self.devlog, 1)
        self.blocked = QComboBox()
        unb = GelButton("Unblock", "#56607f")
        unb.clicked.connect(self._unblock)
        extra = []
        if app.demo:
            for label, fn in (("Fake drive", hw.demo_drive), ("Fake keyboard", lambda: hw.demo_device("keyboard")),
                              ("Fake NIC", lambda: hw.demo_device("network")), ("Fake BadUSB", hw.demo_badusb)):
                b = GelButton(label, MAGENTA, h=30)
                b.clicked.connect(fn)
                extra.append(b)
        ll.addWidget(hbox(QLabel("BLOCKED:"), self.blocked, unb, "stretch", *extra))
        split.addWidget(lp)
        split.setSizes([260, 300])
        v.addWidget(split, 1)
        self._drive_items = {}
        self.refresh_blocked()
        self._drive_sel()

    def set_dma(self, val):
        if val is None:
            self.dma_led.set(DIM); self.dma_lab.setText("Kernel DMA Protection: unknown")
        elif val:
            self.dma_led.set(LIME); self.dma_lab.setText("Kernel DMA Protection: ON")
        else:
            self.dma_led.set(AMBER, True); self.dma_lab.setText("Kernel DMA Protection: OFF (see Alerts)")

    def refresh_blocked(self):
        self.blocked.clear()
        for b in self.app.settings.get("guard_blocked", []):
            self.blocked.addItem(f"{b['vidpid']}  {b['name'][:30]}", b["vidpid"])

    def _unblock(self):
        vp = self.blocked.currentData()
        if vp:
            self.app.hw.unblock(vp)
            self.refresh_blocked()

    def drive_changed(self, d):
        it = self._drive_items.get(d.id)
        lvl = {"clean": "ok", "released": "ok", "suspicious": "warn", "dangerous": "alert", "error": "alert"}.get(d.status, "info")
        files = f"{d.files}…" if d.status == "scanning" else str(d.files or "")
        vals = [d.title + ("  [quarantined]" if d.qpath else ""), d.bus, d.status.upper(), files, d.defender,
                f"{len(d.findings)} (hover)" if d.findings else ""]
        new = row(vals, lvl, d.id)
        if it is None:
            it = new
            self.drives.insertTopLevelItem(0, it)
            self._drive_items[d.id] = it
        else:
            for c in range(len(vals)):
                it.setText(c, vals[c]); it.setForeground(c, new.foreground(c))
        it.setToolTip(5, "\n".join(d.findings[:25]) or "No findings")
        self._drive_sel()

    def _sel_drive(self):
        it = self.drives.currentItem()
        return self.app.hw._by_id(it.data(0, Qt.UserRole)) if it else None

    def _drive_sel(self):
        d = self._sel_drive()
        st = d.status if d else ""
        self.b_release.setEnabled(st in ("clean", "suspicious", "dangerous", "quarantined", "error"))
        self.b_release.setText("Release anyway" if st == "dangerous" else "Release")
        self.b_rescan.setEnabled(bool(d) and st not in ("scanning", "removed"))
        self.b_forget.setEnabled(st in ("removed", "released", "error"))

    def _drive_act(self, fn):
        d = self._sel_drive()
        if d:
            if d.status == "dangerous" and fn == self.app.hw.release and not self.app.confirm(
                    "This drive was flagged DANGEROUS. Give it a drive letter anyway?"):
                return
            fn(d.id)

    def _forget(self):
        d = self._sel_drive()
        if d:
            self.app.hw.forget(d.id)
            self.drives.takeTopLevelItem(self.drives.indexOfTopLevelItem(self.drives.currentItem()))
            self._drive_items.pop(d.id, None)

    def device_logged(self, rec):
        lvl = rec.get("level", "info")
        if "blocked" in rec["action"]:
            lvl = "alert"
        elif "allowed" in rec["action"]:
            lvl = "ok"
        self.devlog.insertTopLevelItem(0, row([fmt_time(time.time()), rec["name"], CATEGORY_LABELS.get(rec["category"], rec["category"]),
                                               rec["bus"], rec["vidpid"], rec["action"].upper()], lvl))
        self.refresh_blocked()


# =========================================================================== Connections
class ConnectionsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(10)
        fw, fl = panel("Windows Firewall", LIME)
        self.fw_leds = {}
        bits = []
        for prof in ("Domain", "Private", "Public"):
            led = LedOrb(DIM)
            lab = QLabel(prof.upper()); lab.setStyleSheet("font-family: Bahnschrift; font-size: 9pt;")
            self.fw_leds[prof] = (led, lab)
            bits += [led, lab]
        self.watch_t = GelToggle("Watch connections", "")
        self.watch_t.setChecked(app.settings.get("watch_connections", True))
        self.watch_t.toggled.connect(lambda on: app.set_setting("watch_connections", on))
        fl.addWidget(hbox(*bits, "stretch", self.watch_t))
        v.addWidget(fw)

        split = QSplitter(Qt.Vertical)
        ip, il = panel("Inbound sessions — someone connected INTO this PC", MAGENTA)
        self.sessions = tree(["Since", "From", "Service", "Program", "Trusted"], [80, 170, 210, 220, 80])
        il.addWidget(self.sessions, 1)
        bi, ti = GelButton("Block address", RED), GelButton("Trust address", "#3f9d00")
        bi.clicked.connect(self._block_ip)
        ti.clicked.connect(self._trust_ip)
        il.addWidget(hbox(bi, ti, dim("Trust = expected source (SCCM, file server, IT jump box). Saved in settings.")))
        split.addWidget(ip)

        lp, ll = panel("Listening — programs accepting connections from the network")
        self.listen = tree(["Proto", "Address", "Port", "Program", "Seen"], [60, 160, 70, 330, 110])
        ll.addWidget(self.listen, 1)
        bp = GelButton("Block program (inbound)", RED)
        bp.clicked.connect(self._block_prog)
        ll.addWidget(hbox(bp, dim("Adds a Windows Firewall rule named 'QuickSentry block …'. Remove it in Windows "
                                  "Defender Firewall > Advanced settings to undo.")))
        split.addWidget(lp)

        cp, cl = panel("Firewall rule changes since QuickSentry started", AMBER)
        self.fwlog = tree(["Time", "Change", "Rule"], [80, 160, 600])
        cl.addWidget(self.fwlog, 1)
        split.addWidget(cp)
        split.setSizes([220, 260, 150])
        v.addWidget(split, 1)

    def render(self, watch):
        for prof, (led, lab) in self.fw_leds.items():
            on = (watch._profiles or {}).get(prof)
            led.set(DIM if on is None else (LIME if on else RED), blink=(on is False))
            lab.setText(prof.upper() + ("" if on is None else (" ON" if on else " OFF")))
        self.sessions.clear()
        for (ip, port), s in sorted(watch.sessions.items(), key=lambda kv: -kv[1]["since"]):
            lvl = "ok" if s["trusted"] else ("alert" if port in netwatch.REMOTE_ADMIN else "warn")
            self.sessions.addTopLevelItem(row([fmt_time(s["since"]), ip, s["service"], s["proc"],
                                               "yes" if s["trusted"] else ""], lvl, {"ip": ip, "path": s.get("path", "")}))
        self.listen.clear()
        for key, l in sorted(watch.listeners.items(), key=lambda kv: (kv[0][0], kv[0][2])):
            lvl = "warn" if l.get("new") else "info"
            self.listen.addTopLevelItem(row([l["proto"], l["laddr"], l["lport"], l["proc"],
                                             "NEW " + fmt_time(l["since"]) if l.get("new") else "at start"],
                                            lvl, {"path": l.get("path", "")}))
        self.fwlog.clear()
        for c in reversed(watch.fw_changes[-200:]):
            self.fwlog.addTopLevelItem(row([fmt_time(c["time"]), c["kind"].upper() + (" · OPENS INBOUND" if c["opens"] else ""),
                                            c["label"]], "warn" if c["opens"] else "info"))

    def _sel(self, t):
        it = t.currentItem()
        return it.data(0, Qt.UserRole) if it else None

    def _block_ip(self):
        d = self._sel(self.sessions)
        if d and self.app.confirm(f"Block all inbound traffic from {d['ip']}?"):
            self.app.firewall_action(netwatch.block_ip, d["ip"])

    def _trust_ip(self):
        d = self._sel(self.sessions)
        if d:
            self.app.trust_ip(d["ip"])

    def _block_prog(self):
        d = self._sel(self.listen)
        if d and self.app.confirm(f"Block inbound connections to:\n{d['path']}?"):
            self.app.firewall_action(netwatch.block_program, d["path"])


# =========================================================================== LAN devices
class LanPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0)
        p, l = panel("Devices your computer has talked to on this network")
        self.tv = tree(["IP address", "Hardware (MAC)", "Maker", "Notes"], [250, 160, 260, 250])
        l.addWidget(self.tv, 1)
        l.addWidget(dim("From this PC's address table. Updated every check."))
        v.addWidget(p)

    def render(self):
        tv, s, res = self.tv, self.app.snap or {}, self.app.results
        tv.clear()
        gw, gm = s.get("gateway_ip"), s.get("gateway_mac")
        n4 = s.get("neighbors4", {})
        counts = {}
        for m in n4.values():
            counts[m] = counts.get(m, 0) + 1
        for ip in sorted(n4, key=lambda x: int(ipaddress.IPv4Address(x))):
            mac = n4[ip]
            notes, lvl = [], INFO
            if ip == gw:
                notes.append("Router")
                if res.get("gateway", {}).get("status") == ALERT:
                    notes.append("MAC CHANGED"); lvl = ALERT
            elif mac == gm:
                notes.append("SAME MAC AS ROUTER"); lvl = ALERT
            elif counts[mac] > 1:
                notes.append("Shares a MAC"); lvl = WARN
            if ip in s.get("neighbors4_static", set()):
                notes.append("Pinned (static)")
            cat = oui.category(mac)
            if cat in ("randomized", "virtual", "sbc", "attack_tool"):
                notes.append({"randomized": "Randomized MAC", "virtual": "Virtual machine", "sbc": "Raspberry Pi",
                              "attack_tool": "Hacking hardware"}[cat])
            tv.addTopLevelItem(row([ip, mac, oui.vendor(mac) or "", ", ".join(notes)], lvl))
        for n in s.get("neighbors6", []):
            tv.addTopLevelItem(row([n["ip"], n["mac"], oui.vendor(n["mac"]) or "", "IPv6 router" if n.get("is_router") else ""], INFO))


# =========================================================================== Path monitor
class PathPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0)
        p, l = panel("Path monitor — for networks you manage", LIME)
        l.addWidget(dim("Repeatedly traces the route to other devices (for example a server across campus). It learns "
                        "the normal path over the first 3 runs, then alerts on new devices in the path, a changed "
                        "route, latency jumps, or the connection going down. A silent bridge/tap won't appear as a hop."))
        self.entry = QLineEdit(app.settings.get("path_targets", ""))
        self.entry.setPlaceholderText("targets: IPs or names, comma-separated")
        self.every = QSpinBox(); self.every.setRange(10, 3600); self.every.setValue(int(app.settings.get("path_interval", 60)))
        self.every.setSuffix(" s")
        self.btn = GelButton("Start", "#3f9d00", w=90)
        acc = GelButton("Accept current path", VIOLET)
        self.btn.clicked.connect(app.toggle_path)
        acc.clicked.connect(self.accept)
        self.entry.setMinimumWidth(340)
        l.addWidget(hbox(self.entry, QLabel("EVERY"), self.every, self.btn, acc))
        self.sel = QComboBox(); self.sel.setMinimumWidth(240)
        self.sel.currentTextChanged.connect(lambda _: self.render())
        self.status = QLabel("")
        self.status.setStyleSheet("font-family: Bahnschrift; font-size: 10pt;")
        l.addWidget(hbox(QLabel("SHOW"), self.sel, self.status))
        self.tv = tree(["Hop", "IP address", "Name", "Time", "MAC (local)", "Maker", "Note"], [50, 130, 230, 70, 140, 170, 150])
        l.addWidget(self.tv, 1)
        v.addWidget(p)

    def current(self):
        h = self.sel.currentText()
        return next((t for t in self.app.path_targets if t.host == h), None)

    def accept(self):
        t = self.current()
        if t and t.hops:
            t.accept_current()
            self.render()

    def render(self):
        t, tv = self.current(), self.tv
        tv.clear()
        if not t:
            self.status.setText("")
            return
        c = LEVEL.get(t.status, LEVEL["info"])[0]
        self.status.setText(f"<span style='color:{c}'>{LEVEL.get(t.status, ('', t.status))[1]}: {t.summary}</span>")
        learning = t.runs <= pathmon.LEARN_RUNS
        for h in t.hops:
            note, lvl = "", INFO
            if h["ip"] is None:
                vals = [h["ttl"], "*", "(no reply)", "", "", "", ""]
            else:
                if h["reached"]:
                    note = "Destination"
                elif self.app.snap and h["ip"] == self.app.snap.get("gateway_ip"):
                    note = "Your router"
                if not learning and h["ip"] not in t.known and h["ip"] != t.ip:
                    note, lvl = "NEW — not in normal path", ALERT
                vals = [h["ttl"], h["ip"], h.get("name", ""), f"{h['rtt']} ms" if h["rtt"] is not None else "",
                        h.get("mac") or "", h.get("vendor") or "", note]
            tv.addTopLevelItem(row(vals, lvl))


# =========================================================================== Net scan
class ScanPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0)
        p, l = panel("Network scan", VIOLET)
        l.addWidget(dim("Finds devices in an IP range and flags suspicious ones (duplicate MACs, randomized MACs, VMs, "
                        "known hacking hardware). Only scan networks you're responsible for."))
        self.entry = QLineEdit(app.settings.get("scan_range", ""))
        self.entry.setPlaceholderText("192.168.1.0/24   10.1.2.10-80   (max 1024)")
        self.entry.setMinimumWidth(300)
        mine = GelButton("Use my subnet", VIOLET)
        self.btn = GelButton("Scan", "#3f9d00", w=100)
        exp = GelButton("Export CSV", "#2d6fd6")
        mine.clicked.connect(app.use_my_subnet)
        self.btn.clicked.connect(app.toggle_scan)
        exp.clicked.connect(app.export_scan)
        l.addWidget(hbox(self.entry, mine, self.btn, "stretch", exp))
        self.prog = QProgressBar(); self.prog.setValue(0)
        self.lab = QLabel(""); self.lab.setStyleSheet("font-family: Consolas;")
        l.addWidget(hbox(self.prog, self.lab, stretch_end=False))
        self.tv = tree(["IP address", "Name", "Hardware (MAC)", "Maker", "Ping", "Notes"], [120, 200, 140, 200, 70, 260])
        l.addWidget(self.tv, 1)
        v.addWidget(p)

    def render(self, rows):
        self.tv.clear()
        for r in rows:
            self.tv.addTopLevelItem(row([r["ip"], r["name"], r["mac"] or "-", r["vendor"] or "",
                                         f"{r['rtt']} ms" if r["rtt"] is not None else "no", "; ".join(r["flags"])],
                                        r["level"] if r["level"] != OK else INFO))


# =========================================================================== Settings
class SettingsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(10)
        top = QWidget(); th = QHBoxLayout(top); th.setContentsMargins(0, 0, 0, 0); th.setSpacing(10)
        n, nl = panel("Network checks", LIME)
        self.toggles = {}
        for k, label, hint in [("check_wifi", "Wi-Fi checks", "fake / evil-twin hotspots"),
                               ("check_first_hop", "Traffic route", "anything between me and the router?"),
                               ("check_ipv6", "IPv6 checks", "rogue IPv6 router / mitm6"),
                               ("check_web", "Internet checks", "sign-in page, HTTPS interception, DNS")]:
            t = GelToggle(label, hint); t.setChecked(bool(app.settings.get(k, True)))
            t.toggled.connect(lambda on, key=k: app.set_setting(key, on))
            nl.addWidget(t); self.toggles[k] = t
        self.interval = QSpinBox(); self.interval.setRange(2, 600); self.interval.setSuffix(" s")
        self.interval.setValue(int(app.settings.get("interval", 5)))
        self.interval.valueChanged.connect(lambda v_: app.set_setting("interval", int(v_)))
        nl.addWidget(hbox(QLabel("CHECK EVERY"), self.interval))
        nl.addStretch(1)
        th.addWidget(n, 1)
        b, bl = panel("Behaviour", VIOLET)
        for k, label, hint in [("popups", "Alert pop-ups", "toast in the corner on red alerts"),
                               ("sound", "Alert sound", ""),
                               ("minimize_to_tray", "Close to tray", "keep guarding after the window closes"),
                               ("autostart_monitoring", "Auto-start", "start network checks on launch")]:
            t = GelToggle(label, hint); t.setChecked(bool(app.settings.get(k, True)))
            t.toggled.connect(lambda on, key=k: app.set_setting(key, on))
            bl.addWidget(t); self.toggles[k] = t
        bl.addStretch(1)
        th.addWidget(b, 1)
        v.addWidget(top)

        a, al = panel("About / data", MAGENTA)
        self.about = QLabel()
        self.about.setStyleSheet(f"font-family: Consolas; font-size: 9pt; color:{TEXT};")
        self.about.setTextInteractionFlags(Qt.TextSelectableByMouse)
        al.addWidget(self.about)
        self.trusted = QComboBox(); self.trusted.setMinimumWidth(200)
        untrust = GelButton("Untrust", "#56607f")
        untrust.clicked.connect(self._untrust)
        al.addWidget(hbox(QLabel("TRUSTED INBOUND SOURCES"), self.trusted, untrust))
        bs = [GelButton("Open data folder", VIOLET), GelButton("Run diagnostics", VIOLET),
              GelButton("Forget remembered networks", AMBER)]
        bs[0].clicked.connect(lambda: app.open_folder(storage.data_dir()))
        bs[1].clicked.connect(app.run_diagnostics)
        bs[2].clicked.connect(app.forget_networks)
        al.addWidget(hbox(*bs))
        al.addStretch(1)
        v.addWidget(a, 1)
        self.refresh()

    def refresh(self):
        from .. import winapi
        self.about.setText(
            f"QuickSentry {__version__}\n"
            f"Data folder:  {storage.data_dir()}   (SYSTEM + Administrators only)\n"
            f"Running as administrator: {'yes' if winapi.is_admin() else ('demo mode' if self.app.demo else 'NO')}\n"
            f"Network checks · hardware guard · connection watch · path monitor · subnet scan")
        self.trusted.clear()
        self.trusted.addItems(self.app.settings.get("trusted_ips", []))

    def _untrust(self):
        ip = self.trusted.currentText()
        if ip:
            self.app.settings["trusted_ips"] = [x for x in self.app.settings.get("trusted_ips", []) if x != ip]
            storage.save_settings(self.app.settings)
            self.app.conn.watch.trusted.discard(ip)
            self.refresh()
