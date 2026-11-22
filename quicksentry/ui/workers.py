"""Background workers. They never touch widgets; they emit Qt signals
(queued across threads automatically)."""
from __future__ import annotations

import queue
import random
import threading
import time

from PySide6.QtCore import QObject, Signal

from .. import pathmon, scanner, storage, sysinfo
from ..engine import CHECKS, Engine
from ..guard import netwatch


class NetMonitor(QObject):
    state = Signal(object, dict, str, list)   # snap, results, overall, events
    error = Signal(str)
    stopped = Signal()

    def __init__(self, settings, known):
        super().__init__()
        self.settings, self.known = settings, known
        self._stop = threading.Event()
        self._cmds: queue.Queue = queue.Queue()
        self._thread = None

    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def start(self):
        if self.running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="net-monitor")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._cmds.put("wake")

    def command(self, c):
        self._cmds.put(c)

    def _run(self):
        engine = Engine(self.settings, self.known)
        while not self._stop.is_set():
            try:
                snap, res, events = engine.step()
                for e in events:
                    e.setdefault("source", "network")
                self.state.emit(snap, dict(res), engine.overall(), events)
                if engine.known_dirty:
                    storage.save_known_networks(engine.known)
                    engine.known_dirty = False
            except Exception as e:  # keep monitoring no matter what
                self.error.emit(f"Monitoring error: {e}")
            try:
                c = self._cmds.get(timeout=max(2, float(self.settings.get("interval", 5))))
                if c == "reset":
                    engine.reset_baseline()
                elif c == "recheck":
                    engine.force_recheck()
            except queue.Empty:
                pass
        self.stopped.emit()


class PathWorker(QObject):
    running_target = Signal(str)
    result = Signal(list)
    error = Signal(str)
    stopped = Signal()

    def __init__(self, targets, interval):
        super().__init__()
        self.targets, self.interval = targets, interval
        self.stop_ev = threading.Event()
        threading.Thread(target=self._run, daemon=True, name="path-monitor").start()

    def _run(self):
        while not self.stop_ev.is_set():
            try:
                snap = sysinfo.snapshot(include_wifi_scan=False)
                net = sysinfo.local_subnet(snap)
                for t in self.targets:
                    if self.stop_ev.is_set():
                        break
                    self.running_target.emit(t.host)
                    evs = pathmon.run_target(t, snap.get("gateway_ip"), net, {**snap.get("neighbors4", {})})
                    for e in evs:
                        e.setdefault("source", "path")
                    self.result.emit(evs)
            except Exception as e:
                self.error.emit(f"Path monitor error: {e}")
            self.stop_ev.wait(self.interval)
        self.stopped.emit()


class ScanWorker(QObject):
    progress = Signal(int, int)
    done = Signal(list, bool)
    error = Signal(str)

    def __init__(self, ips, my_ip, gw):
        super().__init__()
        self.cancel = threading.Event()

        def work():
            try:
                rows = scanner.sweep(ips, lambda d, t: self.progress.emit(d, t), self.cancel, my_ip, gw)
                self.done.emit(rows, self.cancel.is_set())
            except Exception as e:
                self.done.emit([], False)
                self.error.emit(f"Scan error: {e}")
        threading.Thread(target=work, daemon=True, name="subnet-scan").start()


class ConnWorker(QObject):
    update = Signal(list, object)   # events, netwatch.View (a copy, safe to read in the UI)
    error = Signal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.watch = netwatch.Watch(settings.get("trusted_ips", []))
        self._stop = threading.Event()
        self._kick = threading.Event()
        threading.Thread(target=self._run, daemon=True, name="conn-watch").start()

    def stop(self):
        self._stop.set()
        self._kick.set()

    def trust(self, ip):
        self.watch.trusted.add(ip)
        for k, s in self.watch.sessions.items():
            if k[0] == ip:
                s["trusted"] = True

    def _run(self):
        n = 0
        while not self._stop.is_set():
            if self.settings.get("watch_connections", True):
                try:
                    snap = netwatch.collect(with_firewall=(n % 5 == 0))
                    events = self.watch.step(snap)
                    self.update.emit(events, netwatch.View(self.watch))
                except Exception as e:
                    self.error.emit(f"Connection watch error: {e}")
                n += 1
            self._kick.wait(3)
            self._kick.clear()


# ---------------------------------------------------------------- demo feeders
class DemoNet(QObject):
    """Plays back a plausible network state so the UI can be previewed anywhere."""
    state = Signal(object, dict, str, list)
    error = Signal(str)
    stopped = Signal()

    def __init__(self, settings, known):
        super().__init__()
        self._run = False

    def running(self):
        return self._run

    def start(self):
        self._run = True
        snap = {"net_key": "wifi:CoffeeHouse", "net_name": "CoffeeHouse_Guest", "gateway_ip": "192.168.4.1",
                "gateway_mac": "b8:27:eb:12:34:56", "ifindex": 7,
                "adapter": {"ipv4": ["192.168.4.37"], "dns4": ["192.168.4.1"], "dns6": []},
                "wifi": {"ssid": "CoffeeHouse_Guest", "auth": "Open", "name": "Wi-Fi"},
                "neighbors4": {"192.168.4.1": "b8:27:eb:12:34:56", "192.168.4.12": "3c:22:fb:aa:bb:cc",
                               "192.168.4.66": "b8:27:eb:12:34:56", "192.168.4.80": "da:a1:19:00:11:22"},
                "neighbors6": []}
        statuses = {"gateway": "ok", "spoof": "alert", "hardware": "warn", "route": "alert", "settings": "ok",
                    "ipv6": "ok", "wifi": "warn", "history": "info", "portal": "ok", "https": "ok", "dns": "ok"}
        summaries = {"spoof": "192.168.4.66 answers with the router's MAC",
                     "hardware": "Router MAC belongs to Raspberry Pi Foundation",
                     "route": "Traffic passes through 192.168.4.66 before the router",
                     "wifi": "Open network (no password)", "history": "First visit to this network"}
        res = {k: {"key": k, "name": n, "status": statuses[k], "summary": summaries.get(k, "Looks normal"),
                   "details": "Demo data.", "action": ""} for k, n in CHECKS}
        events = [{"time": time.time(), "level": "alert", "title": "ARP spoofing signs",
                   "message": "192.168.4.66 answers with the router's MAC", "details": "", "action": "", "source": "network"}]
        self.state.emit(snap, res, "alert", events)

    def stop(self):
        self._run = False
        self.stopped.emit()

    def command(self, c):
        pass


def demo_conn_watch():
    w = netwatch.Watch(name_of=lambda p: {4: "System", 1200: "svchost.exe", 6600: "nc.exe", 900: "svchost.exe"}.get(p, "app.exe"),
                       path_of=lambda p: "C:\\Users\\Public\\nc.exe" if p == 6600 else "C:\\Windows\\System32\\svchost.exe")
    t = lambda l, lp, r="0.0.0.0", rp=0, s=2, pid=1200: {"proto": "TCP", "laddr": l, "lport": lp, "raddr": r,  # noqa
                                                          "rport": rp, "state": s, "pid": pid}
    base = {"tcp": [t("0.0.0.0", 135), t("0.0.0.0", 445, pid=4), t("0.0.0.0", 3389, pid=900)], "udp": [],
            "rules": {}, "profiles": {"Domain": True, "Private": True, "Public": True}}
    w.step(base)
    snap = {"tcp": base["tcp"] + [t("0.0.0.0", 4444, pid=6600), t("10.1.2.50", 3389, "10.1.9.77", 51234, 5, 900),
                                  t("10.1.2.50", 445, "10.1.0.10", 50110, 5, 4)],
            "udp": [], "rules": {"x": "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\\Users\\Public\\nc.exe|Name=Windows Update Helper|"},
            "profiles": {"Domain": True, "Private": True, "Public": False}}
    events = w.step(snap)
    random.shuffle(events)
    return w, events
