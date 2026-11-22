"""QuickSentry v3 main window: chassis, nav, wiring between engines and pages."""
from __future__ import annotations

import csv
import os
import subprocess
import sys
import threading
import time

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (QAction, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap,
                           QRadialGradient)
from PySide6.QtWidgets import (QApplication, QFileDialog, QLabel, QMenu, QMessageBox, QPlainTextEdit,
                               QStackedWidget, QSystemTrayIcon, QWidget)

from .. import APP_NAME, __version__, actions, pathmon, scanner, storage, sysinfo, winapi
from ..engine import ALERT, WARN
from ..guard import netwatch, win32dev
from ..guard.hardware import HardwareGuard
from . import pages
from .popups import AlertToast, DevicePrompt, KbLockPopup
from .theme import BG0, DIM, LEVEL, LIME, MAGENTA, RANK, STEEL, STEEL_HI, TEXT, VIOLET, col, mono, tech
from .widgets import GelButton, HexButton, NavPod, RadarDome, ThreatTube, Ticker, chamfer, draw_led, neon_text
from .workers import ConnWorker, DemoNet, NetMonitor, PathWorker, ScanWorker, demo_conn_watch

W, H = 1280, 830
TOP = 40
NAV = ["Overview", "Alerts", "Hardware", "Connections", "LAN Devices", "Path Monitor", "Net Scan", "Settings"]
POPUP_COOLDOWN = 120


class _DemoConn:
    def __init__(self):
        self.watch, self.events = demo_conn_watch()

    def stop(self):
        pass

    def trust(self, ip):
        self.watch.trusted.add(ip)


class MainWindow(QWidget):
    def __init__(self, demo=False):
        super().__init__(None, Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(W, H)
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self.demo = demo
        self.settings = storage.load_settings()
        self.known = storage.load_known_networks()
        self.snap, self.results, self.overall = None, {}, "unknown"
        self.alert_count = 0
        self.last_popup = {}
        self.pinned = None
        self.path_targets, self.path_worker = [], None
        self.scan_rows, self.scan_worker = [], None
        self._notif = None
        self._quitting = False
        self._told_tray = False
        self._t = 0.0

        # engines
        self.net = (DemoNet if demo else NetMonitor)(self.settings, self.known)
        self.net.state.connect(self.on_net_state)
        self.net.error.connect(lambda m: self.set_status(m))
        self.net.stopped.connect(lambda: (self.set_status("Network checks stopped."), self.refresh_status()))
        self.hw = HardwareGuard(self.settings, demo=demo)
        self.hw.event.connect(lambda e: self.handle_events([e]))
        self.conn = _DemoConn() if demo else ConnWorker(self.settings)
        self.conn_view = netwatch.View()
        if not demo:
            self.conn.update.connect(self.on_conn)
            self.conn.error.connect(self.set_status)

        # chrome
        self.dome = RadarDome(self)
        self.dome.setGeometry(18, 0, 196, 196)
        self.ticker = Ticker(self)
        self.ticker.setGeometry(236, 112, W - 236 - 30, 22)
        self.threat = ThreatTube(self)
        self.threat.move(W - 380, 52)
        self.b_min, self.b_close = HexButton("-", LIME, self), HexButton("x", MAGENTA, self)
        self.b_min.move(W - 100, 58); self.b_close.move(W - 64, 58)
        self.b_min.clicked.connect(self.showMinimized)
        self.b_close.clicked.connect(self.close)

        self.navs = {}
        for i, name in enumerate(NAV):
            n = NavPod(name, self)
            n.setGeometry(22, 214 + i * 50, 196, 46)
            n.clicked.connect(lambda _=False, nm=name: self.goto(nm))
            self.navs[name] = n
        self.b_net = GelButton("Pause net checks", "#56607f", self, h=34, w=196)
        self.b_net.move(22, 640)
        self.b_net.clicked.connect(self.toggle_net)
        self.armed = QLabel(self)
        self.armed.setGeometry(26, 682, 196, 60)
        self.armed.setWordWrap(True)

        self.stack = QStackedWidget(self)
        self.stack.setGeometry(236, 146, W - 236 - 26, H - 146 - 50)
        self.p_over = pages.OverviewPage(self)
        self.p_alerts = pages.AlertsPage(self)
        self.p_hw = pages.HardwarePage(self)
        self.p_conn = pages.ConnectionsPage(self)
        self.p_lan = pages.LanPage(self)
        self.p_path = pages.PathPage(self)
        self.p_scan = pages.ScanPage(self)
        self.p_set = pages.SettingsPage(self)
        self.page_of = dict(zip(NAV, [self.p_over, self.p_alerts, self.p_hw, self.p_conn, self.p_lan,
                                      self.p_path, self.p_scan, self.p_set]))
        for pg in self.page_of.values():
            self.stack.addWidget(pg)
        self.statusbar = QLabel(self)
        self.statusbar.setGeometry(240, H - 40, W - 280, 20)
        self.statusbar.setStyleSheet(f"color:{DIM}; font-family: Consolas; font-size: 8pt;")

        # guard wiring
        self.kb_popup = KbLockPopup()
        self.kb_popup.allow.connect(self.hw.kb_allow)
        self.kb_popup.block.connect(self.hw.kb_block)
        self.dev_prompt = DevicePrompt()
        self.dev_prompt.allow.connect(self.hw.allow)
        self.dev_prompt.block.connect(self.hw.block)
        self.toast = AlertToast()
        self.toast.clicked.connect(lambda: (self.show_window(), self.goto("Alerts")))
        self.hw.kb_locked.connect(lambda on, reason, code: (self.kb_popup.show_lock(reason, code) if on
                                                            else self.kb_popup.hide_lock(), self.refresh_status()))
        self.hw.pending_changed.connect(lambda pend: (self.dev_prompt.set_pending(pend), self.refresh_status()))
        self.hw.drive_changed.connect(lambda d: (self.p_hw.drive_changed(d), self.refresh_status()))
        self.hw.device_logged.connect(self.p_hw.device_logged)

        self._setup_tray()
        self.goto("Overview")
        tm = QTimer(self); tm.timeout.connect(self._tick); tm.start(80)
        QTimer.singleShot(0, self._start)

    # ------------------------------------------------------------ startup
    def _start(self):
        self.set_status("Starting…")
        self.hw.start()
        self.p_hw.set_dma(self.hw.dma if not self.demo else True)
        if self.settings.get("autostart_monitoring", True):
            self.net.start()
        if self.demo:
            self.on_conn(self.conn.events, netwatch.View(self.conn.watch))
        self.refresh_status()

    def register_device_events(self):
        if not self.demo:
            self._notif = win32dev.register_all_interfaces(int(self.winId()))

    def nativeEvent(self, event_type, message):  # noqa: N802
        if not self.demo and win32dev.IS_WINDOWS and bytes(event_type) == b"windows_generic_MSG":
            import ctypes.wintypes as wt
            msg = wt.MSG.from_address(int(message))
            if msg.message == win32dev.WM_DEVICECHANGE:
                try:
                    parsed = win32dev.parse_device_change(msg.wParam, msg.lParam)
                    if parsed:
                        self.hw.on_device_event(*parsed)
                except Exception as e:
                    self.set_status(f"device event error: {e}")
        return False, 0

    # ------------------------------------------------------------ navigation / status
    def goto(self, name):
        for n, pod in self.navs.items():
            pod.setChecked(n == name)
        self.stack.setCurrentWidget(self.page_of[name])
        if name == "Settings":
            self.p_set.refresh()

    def set_status(self, text):
        self.statusbar.setText(text)

    def section_levels(self):
        net = self.overall if self.net.running() else "unknown"
        return net, self.hw.summary(), self.conn_view.summary() if self.settings.get("watch_connections", True) else "off"

    def refresh_status(self):
        net, hw, conn = self.section_levels()
        overall = max((net, hw, conn), key=lambda l: RANK.get(l, 0))
        self.threat.set(overall)
        self.dome.set_level(overall)
        title, sub = pages.BANNER.get(overall, pages.BANNER["unknown"])
        bad = [r for r in self.results.values() if r["status"] == net and net in (WARN, ALERT)]
        if bad:
            sub = f"{bad[0]['name']}: {bad[0]['summary']}" + (f"  (+{len(bad) - 1} more)" if len(bad) > 1 else "")
        if hw == ALERT and overall == ALERT and net != ALERT:
            sub = "Hardware guard: check the Hardware page."
        if self.snap is not None and not self.snap.get("net_key") and self.net.running():
            title, sub = "NOT CONNECTED", "Waiting for a network connection. Hardware and port guards are still on."
        self.p_over.banner.set(overall, title, sub)
        nm = (self.snap or {}).get("net_name") or "no network"
        self.p_over.pod_net.set(net, f"{nm} · {LEVEL.get(net, LEVEL['unknown'])[1]}" if self.net.running() else "paused")
        pend = len(self.hw.pending)
        drives = len([d for d in self.hw.drives.values() if d.status not in ("removed",)])
        self.p_over.pod_hw.set(hw, ("KEYBOARD FROZEN · " if self.hw.guard.locked else "") +
                               (f"{pend} on hold · " if pend else "") + f"{drives} drive(s) seen · guard armed")
        w = self.conn_view
        self.p_over.pod_conn.set(conn, f"{len(w.listeners)} listening · {len(w.sessions)} inbound session(s)")
        self.navs["Overview"].set_status(LEVEL.get(overall, LEVEL["unknown"])[0])
        self.navs["Alerts"].set_status(MAGENTA if self.alert_count else LIME, self.alert_count)
        self.navs["Hardware"].set_status(LEVEL.get(hw, LEVEL["ok"])[0], pend)
        self.navs["Connections"].set_status(LEVEL.get(conn, LEVEL["ok"])[0])
        self.navs["LAN Devices"].set_status(LEVEL.get(net, LEVEL["unknown"])[0])
        pt = self.path_worker and not self.path_worker.stop_ev.is_set()
        self.navs["Path Monitor"].set_status(LIME if pt else STEEL)
        self.navs["Net Scan"].set_status(LIME if self.scan_worker else STEEL)
        self.navs["Settings"].set_status(VIOLET)
        self.b_net.setText("Pause net checks" if self.net.running() else "Start net checks")
        admin = winapi.is_admin()
        self.armed.setText(f"<span style='color:{LIME if admin or self.demo else MAGENTA}; font-family:Bahnschrift;"
                           f" font-size:10pt;'>{'● SENTRY ARMED' if admin or self.demo else '● NOT ELEVATED'}</span><br>"
                           f"<span style='color:{DIM}; font-family:Consolas; font-size:7.5pt;'>"
                           f"{'DEMO MODE — nothing real is touched' if self.demo else 'admin · hardware + port guard live'}</span>")
        if self.tray:
            self.tray.setToolTip(f"QuickSentry — threat level {LEVEL.get(overall, LEVEL['unknown'])[1]}")
        self.update()

    def _tick(self):
        self._t += 0.08

    # ------------------------------------------------------------ events
    def on_net_state(self, snap, results, overall, events):
        self.snap, self.results, self.overall = snap, results, overall
        self.p_over.render()
        self.p_lan.render()
        self.handle_events(events)
        self.set_status(f"last check {pages.fmt_time(time.time())}  |  every {self.settings.get('interval', 5)}s  |  "
                        f"data: {storage.data_dir()}")
        if self.pinned and snap.get("net_key") and snap.get("net_key") != self.pinned[2]:
            ifi, ip, _ = self.pinned
            self.pinned = None
            self.p_over.pin_btn.setText("Pin router address")
            if self.confirm(f"You left the network where router {ip} was pinned. Remove the pin now? (Recommended)"):
                actions.unpin_gateway(ifi, ip)
        self.refresh_status()

    def on_conn(self, events, view):
        self.conn_view = view
        self.p_conn.render(view)
        self.handle_events(events)
        self.refresh_status()

    def handle_events(self, events):
        for e in events:
            e.setdefault("source", "network")
            storage.log_line(f"[{e['level'].upper()}] [{e['source']}] {e['title']}: {e['message']}" +
                             (" | " + e["details"].replace("\n", " | ") if e.get("details") else ""))
            self.p_alerts.add(e)
            self.ticker.push(f"{e['source']}: {e['title']}", e["level"])
            self.dome.blip(e["level"])
            if e["level"] in (WARN, ALERT):
                self.alert_count += 1
                if self.tray and e["level"] == WARN:
                    self.tray.showMessage(f"{LEVEL[e['level']][1]}: {e['title']}", e["message"],
                                          QSystemTrayIcon.Warning, 6000)
            if e["level"] == ALERT:
                if self.settings.get("sound", True):
                    winapi.beep()
                key = e["title"]
                if self.settings.get("popups", True) and time.time() - self.last_popup.get(key, 0) > POPUP_COOLDOWN:
                    self.last_popup[key] = time.time()
                    self.toast.pop(e)
        if events:
            self.refresh_status()

    # ------------------------------------------------------------ overview actions
    def toggle_net(self):
        if self.net.running():
            self.net.stop()
        else:
            self.net.start()
        QTimer.singleShot(300, self.refresh_status)

    def reset_baseline(self):
        if not self.net.running():
            return
        if self.overall == ALERT and not self.confirm(
                "There is an active ALERT. Resetting accepts the current state as normal.\n\n"
                "Only do this if you know why it changed. Reset?"):
            return
        self.net.command("reset")

    def disconnect_wifi(self):
        s = self.snap or {}
        if not s.get("wifi"):
            self.info("You're not connected to Wi-Fi.")
            return
        if self.confirm(f"Disconnect from '{s['wifi'].get('ssid')}' now?"):
            ok, out = actions.disconnect_wifi(s["wifi"]["name"])
            if not ok:
                self.info(f"Windows said:\n{out or 'no response'}")

    def toggle_pin(self):
        s = self.snap or {}
        btn = self.p_over.pin_btn
        if self.pinned:
            ifi, ip, _ = self.pinned
            actions.unpin_gateway(ifi, ip)
            self.pinned = None
            btn.setText("Pin router address")
            return
        gw, gm, ifi = s.get("gateway_ip"), s.get("gateway_mac"), s.get("ifindex")
        if not (gw and gm and ifi):
            self.info("Router address not known yet.")
            return
        if self.overall == ALERT:
            self.info("There's an active alert, so the current router address may be the attacker's. Not pinning.")
            return
        from .. import oui
        if not self.confirm(f"Pin router {gw} to {gm} ({oui.vendor(gm) or 'unknown maker'})?\n\nWindows will "
                            "ignore anyone else claiming to be the router (blocks ARP spoofing). Lasts until you "
                            "unpin or restart."):
            return
        actions.pin_gateway(ifi, gw, gm)

        def verify():
            if actions.is_pinned(ifi, gw):
                self.pinned = (ifi, gw, s.get("net_key"))
                btn.setText("Unpin router address")
            else:
                self.info("The pin didn't take effect.")
        QTimer.singleShot(2000, verify)

    def save_report(self):
        text = actions.build_report(self.snap, self.results, self.overall,
                                    [self.p_alerts.tv.topLevelItem(i).data(0, Qt.UserRole)
                                     for i in range(self.p_alerts.tv.topLevelItemCount())][::-1],
                                    self.path_targets, self.scan_rows)
        text += self._guard_report()
        path = actions.save_report(text)
        if self.confirm(f"Report saved:\n{path}\n\nOpen it now?"):
            self.open_folder(path)

    def _guard_report(self):
        out = ["", "=" * 60, "HARDWARE GUARD", "=" * 60]
        out.append(f"Kernel DMA Protection: {self.hw.dma}")
        for d in self.hw.drives.values():
            out.append(f"Drive {d.title} [{d.bus}] {d.status} files={d.files} defender={d.defender}")
            out += ["    " + f for f in d.findings[:20]]
        for r in self.hw.devices[-50:]:
            out.append(f"{time.strftime('%H:%M:%S', time.localtime(r['time']))} {r['category']:<11} {r['name']} "
                       f"[{r['vidpid']}] {r['bus']} -> {r['action']}")
        w = self.conn_view
        out += ["", "=" * 60, "CONNECTIONS", "=" * 60, f"Firewall profiles: {w._profiles}"]
        for (ip, port), s in w.sessions.items():
            out.append(f"INBOUND {ip} -> {s['service']} ({s['proc']}) trusted={s['trusted']}")
        for k, l in w.listeners.items():
            out.append(f"LISTEN {l['proto']} {l['laddr']}:{l['lport']} {l['proc']}{' NEW' if l.get('new') else ''}")
        for c in w.fw_changes[-50:]:
            out.append(f"FW {c['kind']} {c['label']}")
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------ connections actions
    def firewall_action(self, fn, arg):
        try:
            ok, out = fn(arg)
        except ValueError as e:
            ok, out = False, str(e)
        if self.demo:
            ok, out = True, "demo"
        self.handle_events([{"time": time.time(), "level": "info" if ok else "warn", "source": "connections",
                             "title": "Firewall rule added" if ok else "Firewall rule failed",
                             "message": f"{fn.__name__.replace('_', ' ')}: {arg}", "details": out, "action": ""}])

    def trust_ip(self, ip):
        lst = self.settings.setdefault("trusted_ips", [])
        if ip not in lst:
            lst.append(ip)
            storage.save_settings(self.settings)
        self.conn.trust(ip)
        self.conn_view.trusted.add(ip)
        for k, sess in self.conn_view.sessions.items():
            if k[0] == ip:
                sess["trusted"] = True
        self.p_conn.render(self.conn_view)
        self.refresh_status()

    def set_setting(self, key, value):
        self.settings[key] = value
        storage.save_settings(self.settings)
        if key in ("check_wifi", "check_first_hop", "check_ipv6", "check_web", "interval"):
            self.net.command("recheck")
        self.refresh_status()

    # ------------------------------------------------------------ path / scan
    def toggle_path(self):
        pg = self.p_path
        if self.path_worker and not self.path_worker.stop_ev.is_set():
            self.path_worker.stop_ev.set()
            pg.btn.setText("Stopping…")
            return
        hosts = [h.strip() for h in pg.entry.text().split(",") if h.strip()]
        if not hosts:
            self.info("Enter at least one target IP or hostname.")
            return
        interval = pg.every.value()
        self.settings["path_targets"], self.settings["path_interval"] = ", ".join(hosts), interval
        storage.save_settings(self.settings)
        old = {t.host: t for t in self.path_targets}
        self.path_targets = [old.get(h) or pathmon.Target(h) for h in hosts]
        pg.sel.blockSignals(True)
        pg.sel.clear(); pg.sel.addItems(hosts)
        pg.sel.blockSignals(False)
        if self.demo:
            self.info("Path monitor needs Windows (demo mode).")
            return
        self.path_worker = PathWorker(self.path_targets, interval)
        self.path_worker.running_target.connect(lambda h: pg.status.setText(f"Tracing route to {h}…")
                                                if pg.sel.currentText() == h else None)
        self.path_worker.result.connect(lambda evs: (self.handle_events(evs), pg.render()))
        self.path_worker.error.connect(self.set_status)
        self.path_worker.stopped.connect(lambda: (pg.btn.setText("Start"), self.refresh_status()))
        pg.btn.setText("Stop")
        pg.render()
        self.refresh_status()

    def use_my_subnet(self):
        net = sysinfo.local_subnet(self.snap or {})
        if not net:
            self.info("Couldn't detect your subnet yet. Start network checks first or type a range.")
            return
        self.p_scan.entry.setText(str(net))

    def toggle_scan(self):
        pg = self.p_scan
        if self.scan_worker is not None:
            self.scan_worker.cancel.set()
            pg.btn.setText("Cancelling…")
            return
        spec = pg.entry.text().strip()
        ips, err = scanner.parse_targets(spec, sysinfo.local_subnet(self.snap or {}))
        if err:
            self.info(err)
            return
        self.settings["scan_range"] = spec
        storage.save_settings(self.settings)
        if self.demo:
            self.info("Network scan needs Windows (demo mode).")
            return
        s = self.snap or {}
        my_ip = ((s.get("adapter") or {}).get("ipv4") or [None])[0]
        pg.prog.setMaximum(len(ips)); pg.prog.setValue(0)
        pg.lab.setText(f"Scanning {len(ips)} addresses…")
        pg.btn.setText("Cancel")
        self.scan_worker = ScanWorker(ips, my_ip, s.get("gateway_ip"))
        self.scan_worker.progress.connect(lambda d, t: (pg.prog.setValue(d), pg.lab.setText(f"{d} / {t}")))
        self.scan_worker.error.connect(self.set_status)
        self.scan_worker.done.connect(self._scan_done)
        self.refresh_status()

    def _scan_done(self, rows, cancelled):
        pg = self.p_scan
        self.scan_worker = None
        pg.btn.setText("Scan")
        if cancelled:
            pg.lab.setText("Scan cancelled.")
        else:
            self.scan_rows = rows
            pg.render(rows)
            flagged = sum(1 for r in rows if r["level"] != "ok")
            pg.lab.setText(f"Found {len(rows)} devices" + (f", {flagged} flagged" if flagged else ""))
        self.refresh_status()

    def export_scan(self):
        if not self.scan_rows:
            self.info("Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export scan", os.path.join(
            storage.reports_dir(), time.strftime("scan-%Y%m%d-%H%M%S.csv")), "CSV (*.csv)")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["IP", "Name", "MAC", "Maker", "Ping ms", "Notes"])
                for r in self.scan_rows:
                    w.writerow([r["ip"], r["name"], r["mac"], r["vendor"], r["rtt"], "; ".join(r["flags"])])

    # ------------------------------------------------------------ settings actions
    def forget_networks(self):
        if self.confirm("Forget every network QuickSentry has remembered?"):
            self.known.clear()
            storage.save_known_networks(self.known)
            self.net.command("reset")

    def run_diagnostics(self):
        win = QPlainTextEdit()
        win.setWindowTitle("QuickSentry diagnostics")
        win.resize(860, 560)
        win.setReadOnly(True)
        win.setPlainText("Running diagnostics (takes ~15 seconds)…")
        win.show()
        self._diag = win

        holder = {}

        def work():
            out = actions.diagnostics()
            path = os.path.join(storage.reports_dir(), time.strftime("diagnostics-%Y%m%d-%H%M%S.txt"))
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(out)
                out += f"\n\nSaved to {path}"
            except OSError:
                pass
            holder["out"] = out
        th = threading.Thread(target=work, daemon=True)
        th.start()

        def poll():
            if "out" in holder:
                win.setPlainText(holder["out"])
            else:
                QTimer.singleShot(500, poll)
        QTimer.singleShot(500, poll)

    # ------------------------------------------------------------ helpers
    def confirm(self, text):
        return QMessageBox.question(self, APP_NAME, text) == QMessageBox.Yes

    def info(self, text):
        QMessageBox.information(self, APP_NAME, text)

    @staticmethod
    def open_folder(path):
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    # ------------------------------------------------------------ tray / window
    @staticmethod
    def app_icon():
        pm = QPixmap(64, 64)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        g = QRadialGradient(QPointF(32, 40), 34)
        g.setColorAt(0, col("#1d4a12")); g.setColorAt(1, col("#020502"))
        p.setBrush(g); p.setPen(QPen(col(STEEL_HI), 3))
        p.drawEllipse(QRectF(4, 4, 56, 56))
        p.setPen(QPen(col(LIME, 160), 1.5)); p.setBrush(Qt.NoBrush)
        p.drawEllipse(QRectF(14, 14, 36, 36))
        p.setBrush(col("#ffffff")); p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(32, 32), 11, 11)
        p.setBrush(col(VIOLET)); p.drawEllipse(QPointF(32, 32), 6, 6)
        p.setBrush(col("#000000")); p.drawEllipse(QPointF(32, 32), 2.6, 2.6)
        p.setBrush(col("#ffffff", 120)); p.drawEllipse(QRectF(14, 8, 30, 16))
        p.end()
        return QIcon(pm)

    def _setup_tray(self):
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self.app_icon(), self)
        m = QMenu()
        a1 = QAction("Show QuickSentry", m); a1.triggered.connect(self.show_window)
        a2 = QAction("Pause / resume network checks", m); a2.triggered.connect(self.toggle_net)
        a3 = QAction("Exit (turns all protection off)", m); a3.triggered.connect(self.quit_app)
        m.addAction(a1); m.addAction(a2); m.addSeparator(); m.addAction(a3)
        self.tray.setContextMenu(m)
        self._menu = m
        self.tray.activated.connect(lambda r: self.show_window() if r == QSystemTrayIcon.Trigger else None)
        self.tray.show()

    def show_window(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    def closeEvent(self, e):
        if not self._quitting and self.tray and self.settings.get("minimize_to_tray", True):
            e.ignore()
            self.hide()
            if not self._told_tray:
                self._told_tray = True
                self.tray.showMessage(APP_NAME, "Still guarding in the background. Right-click the tray icon to exit.",
                                      QSystemTrayIcon.Information, 4000)
            return
        if self.pinned and self.confirm("Remove the router pin before exiting? (Recommended)"):
            actions.unpin_gateway(self.pinned[0], self.pinned[1])
        self.net.stop()
        self.conn.stop()
        if self.path_worker:
            self.path_worker.stop_ev.set()
        if self.scan_worker:
            self.scan_worker.cancel.set()
        self.hw.shutdown()
        win32dev.unregister(self._notif)
        try:
            storage.save_known_networks(self.known)
        except OSError:
            pass
        for w in (self.kb_popup, self.dev_prompt, self.toast):
            w.hide()
        if self.tray:
            self.tray.hide()
        e.accept()
        QApplication.quit()

    def quit_app(self):
        self._quitting = True
        self.close()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton and self.windowHandle():
            self.windowHandle().startSystemMove()

    # ------------------------------------------------------------ chassis painting
    def chassis(self):
        r = QRectF(8, TOP, W - 16, H - TOP - 8)
        body = QPainterPath()
        c = 30
        body.moveTo(r.left() + 220, r.top())
        body.lineTo(r.right() - 330, r.top())
        body.lineTo(r.right() - 300, r.top() - 18)         # raised right 'visor'
        body.lineTo(r.right() - c, r.top() - 18)
        body.lineTo(r.right(), r.top() - 18 + c)
        body.lineTo(r.right(), r.bottom() - c)
        body.lineTo(r.right() - c, r.bottom())
        body.lineTo(r.left() + 250, r.bottom())
        body.lineTo(r.left() + 226, r.bottom() - 24)
        body.lineTo(r.left() + c, r.bottom() - 24)
        body.lineTo(r.left(), r.bottom() - 24 - c)
        body.lineTo(r.left(), r.top() + 120)
        body.lineTo(r.left() + 20, r.top())
        body.closeSubpath()
        dome = QPainterPath()
        dome.addEllipse(QPointF(116, 98), 104, 104)
        return body.united(dome)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        body = self.chassis()
        for i in range(10, 0, -2):
            p.fillPath(body.translated(0, i * 0.8), col("#000000", 14))
        g = QLinearGradient(QPointF(0, 0), QPointF(0, H))
        g.setColorAt(0, col("#1a2140")); g.setColorAt(0.25, col("#0b1022")); g.setColorAt(1, col(BG0))
        p.fillPath(body, g)
        p.save(); p.setClipPath(body)
        # perspective grid floor (very Y2K)
        p.setPen(QPen(col(VIOLET, 26), 1))
        for x in range(0, W, 40):
            p.drawLine(QPointF(x, 150), QPointF(x, H))
        for y in range(150, H, 40):
            p.drawLine(QPointF(0, y), QPointF(W, y))
        glow = QRadialGradient(QPointF(W * 0.62, H + 80), W * 0.55)
        glow.setColorAt(0, col(VIOLET, 70)); glow.setColorAt(1, col(VIOLET, 0))
        p.fillRect(self.rect(), glow)
        # brushed-metal top bar
        bar = QRectF(0, 20, W, 124)
        bg = QLinearGradient(bar.topLeft(), bar.bottomLeft())
        bg.setColorAt(0, col("#3b4569")); bg.setColorAt(0.08, col("#232b48")); bg.setColorAt(0.9, col("#141a30"))
        bg.setColorAt(1, col("#070a15"))
        p.fillRect(bar, bg)
        p.setPen(QPen(col("#ffffff", 10), 1))
        for y in range(22, 142, 2):
            p.drawLine(QPointF(0, y), QPointF(W, y))
        p.setPen(QPen(col(LIME, 160), 2))
        p.drawLine(QPointF(220, 142), QPointF(W, 142))
        # nav rail
        rail = QRectF(14, 196, 212, 556)
        rp = chamfer(rail, 16)
        p.fillPath(rp, col("#05070f", 200))
        p.setPen(QPen(col(STEEL, 200), 1)); p.drawPath(rp)
        p.restore()
        p.setPen(QPen(col(STEEL_HI, 230), 2)); p.drawPath(body)
        p.setPen(QPen(col("#000000", 200), 1)); p.drawPath(body.translated(0, 1.5))
        # title
        neon_text(p, QRectF(236, 44, 560, 46), "QUICKSENTRY", tech(30), LIME)
        p.setFont(tech(9)); p.setPen(col(MAGENTA))
        p.drawText(QRectF(240, 84, 600, 20), Qt.AlignLeft | Qt.AlignVCenter,
                   f"NETWORK + PORT SENTRY  //  v{__version__}" + ("  //  DEMO MODE" if self.demo else ""))
        # rivets
        for x, y in ((W - 24, 40), (W - 24, H - 26), (250, H - 22)):
            draw_led(p, QRectF(x - 4, y - 4, 8, 8), STEEL_HI)
