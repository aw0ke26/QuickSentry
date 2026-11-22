"""Hardware guard: one gate for every newly connected device.

Per-category policy:
  log    allow quietly (logged)
  alert  allow, but raise a warning
  ask    hold it until you approve
           keyboard -> all typing frozen until a human types a code
           storage  -> drive quarantined (no letter) and scanned
           others   -> device disabled until you click Allow
  block  disable it immediately

It also groups everything that arrives from one physical device, so a
"flash drive" that is secretly also a keyboard (BadUSB / O.MG cable) is
called out as such.
"""
from __future__ import annotations

import itertools
import os
import random
import subprocess
import threading
import time
from dataclasses import dataclass, field

from PySide6.QtCore import QObject, QTimer, Signal

from .. import storage
from . import filescan
from . import win32dev as w
from .kbguard import KeyboardGuard

INFO, WARN, ALERT = "info", "warn", "alert"
POLICIES = ("log", "alert", "ask", "block")
DEFAULT_POLICIES = {
    "keyboard": "ask", "storage": "ask", "network": "ask", "phone": "ask", "thunderbolt": "ask",
    "bluetooth": "alert", "serial": "alert", "usb_other": "log", "mouse": "log", "camera": "log",
    "audio": "log", "display": "log", "printer": "log", "smartcard": "log",
}
POLICY_HELP = {
    "keyboard": "Fake keyboards (Rubber Ducky, O.MG cable) type attacks in milliseconds.",
    "storage": "Ask = quarantine with no drive letter and scan before you can open it.",
    "network": "Fake USB network adapters (LAN Turtle, PoisonTap) can hijack your traffic.",
    "phone": "Phones and cameras (MTP) have no drive letter, so normal drive scanning misses them.",
    "thunderbolt": "Thunderbolt and PCIe devices can read memory directly. Kernel DMA Protection is the real fix.",
    "bluetooth": "New Bluetooth connections. Bluetooth keyboards still go through the keyboard rule.",
    "serial": "Serial/COM devices (Arduino, programmers, modems).",
}
BADUSB_COMBOS = {"storage", "network", "phone"}
GROUP_WINDOW = 4.0
_ids = itertools.count(1)


def ev(level, title, message, details="", action=""):
    return {"time": time.time(), "level": level, "title": title, "message": message,
            "details": details, "action": action, "source": "hardware"}


def quarantine_root():
    return os.path.join(storage.data_dir(), "quarantine")


def rules_dir():
    import sys
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    return os.path.join(base, "rules")


def _quiet(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return None


@dataclass
class Drive:
    vol_guid: str
    letter: str | None
    label: str = ""
    fs: str = ""
    vendor: str = ""
    product: str = ""
    bus: str = ""
    status: str = "quarantined"   # quarantined|scanning|clean|suspicious|dangerous|released|removed|error|in place
    qpath: str | None = None
    files: int = 0
    findings: list = field(default_factory=list)
    defender: str = ""
    id: int = field(default_factory=lambda: next(_ids))
    cancel: threading.Event = field(default_factory=threading.Event)

    @property
    def title(self):
        name = self.label or " ".join(x for x in (self.vendor, self.product) if x) or "Unnamed drive"
        return f"{name} ({self.letter}:)" if self.letter else name


class HardwareGuard(QObject):
    event = Signal(dict)
    drive_changed = Signal(object)
    device_logged = Signal(dict)        # a row for the device log
    pending_changed = Signal(list)      # devices waiting for Allow/Block
    kb_locked = Signal(bool, str, str)  # locked, reason, code
    status_changed = Signal()

    def __init__(self, settings: dict, demo: bool = False):
        super().__init__()
        self.settings = settings
        self.demo = demo
        self.drives: dict[str, Drive] = {}
        self.devices: list[dict] = []
        self.pending: dict[int, dict] = {}
        self._groups: dict[str, dict] = {}
        self._recent: dict[tuple, float] = {}
        self._suppress: dict[str, float] = {}
        self._session_allowed: set[str] = set()
        self._iface_to_guid: dict[str, str] = {}
        self._kb_root = ""
        self.dma = w.dma_protection()
        self.guard = KeyboardGuard()
        self.guard.locked_changed.connect(self._on_lock)
        self.guard.unlocked_by_code.connect(lambda: self._unlocked("Unlock code typed by a human"))
        self.guard.hook_failed.connect(lambda m: self.event.emit(ev(WARN, "Keyboard guard failed", m)))

    # ------------------------------------------------------------ settings
    def policy(self, cat):
        return self.settings.get("guard_policies", {}).get(cat, DEFAULT_POLICIES.get(cat, "log"))

    def set_policy(self, cat, value):
        self.settings.setdefault("guard_policies", dict(DEFAULT_POLICIES))[cat] = value
        storage.save_settings(self.settings)

    def start(self):
        self.settings.setdefault("guard_policies", dict(DEFAULT_POLICIES))
        for k, v in DEFAULT_POLICIES.items():
            self.settings["guard_policies"].setdefault(k, v)
        self.guard.speed_trap = self.settings.get("guard_speed_trap", True)
        if not self.demo:
            os.makedirs(quarantine_root(), exist_ok=True)
            self._cleanup_stale_quarantine()
            self.apply_autoplay(self.settings.get("guard_autoplay", True))
            if self.settings.get("guard_strict", False):
                self.apply_strict(True)
            self.guard.start()
        if self.dma is False:
            self.event.emit(ev(WARN, "Kernel DMA Protection is off",
                               "Thunderbolt/PCIe devices could read memory directly on this PC.",
                               "QuickSentry can spot new Thunderbolt devices, but it can't stop a direct "
                               "memory read once one is plugged in.",
                               "Turn on Kernel DMA Protection in the BIOS/UEFI (it may be called VT-d, "
                               "IOMMU or 'Thunderbolt security'), or avoid unknown docks."))

    def shutdown(self):
        self.guard.stop()
        if self.demo:
            return
        if self.settings.get("guard_strict", False):
            _quiet(["mountvol", "/E"])        # never leave the PC letter-less
        for d in list(self.drives.values()):
            d.cancel.set()
            if d.qpath:
                self._unmount_q(d)
                if d.status not in ("dangerous",):
                    self._assign_letter(d)
        for p in list(self.pending.values()):
            w.set_device_enabled(p["instance"], True)   # don't strand held devices

    def apply_autoplay(self, on: bool):
        if on and not self.demo:
            _quiet(["reg", "add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "/v", "NoDriveTypeAutoRun", "/t", "REG_DWORD", "/d", "255", "/f"])

    def apply_strict(self, on: bool):
        if not self.demo:
            _quiet(["mountvol", "/N" if on else "/E"])

    def set_option(self, key, value):
        self.settings[key] = value
        storage.save_settings(self.settings)
        if key == "guard_speed_trap":
            self.guard.speed_trap = value
        elif key == "guard_autoplay":
            self.apply_autoplay(value)
        elif key == "guard_strict":
            self.apply_strict(value)

    def _cleanup_stale_quarantine(self):
        try:
            for name in os.listdir(quarantine_root()):
                p = os.path.join(quarantine_root(), name)
                w.delete_mount_point(p)
                try:
                    os.rmdir(p)
                except OSError:
                    pass
        except OSError:
            pass

    # ------------------------------------------------------------ device events
    def on_device_event(self, event, kind, payload):
        if kind == "volume":
            if event == "arrival":
                for L in payload:
                    self._volume_letter_arrived(L)
            return
        guid, path = payload
        if guid == w.GUID_VOLUME:
            if event == "arrival":
                QTimer.singleShot(1200, lambda p=path: self._volume_iface_arrived(p))
            else:
                g = self._iface_to_guid.pop(path.lower(), None)
                if g and g in self.drives:
                    self._drive_removed(self.drives[g])
            return
        if event == "arrival":
            self._interface_arrived(guid, path)
        else:
            inst = w.interface_path_to_instance_id(path)
            for pid, p in list(self.pending.items()):
                if p["instance"] == inst and time.time() - p["time"] > 3:
                    self.pending.pop(pid)        # unplugged while held
                    self.pending_changed.emit(list(self.pending.values()))

    def _interface_arrived(self, guid, path):
        inst = w.interface_path_to_instance_id(path)
        cat = w.categorize(guid, inst)
        if not cat or cat == "storage":
            return
        now = time.time()
        if w.is_software(inst):
            if cat == "network":
                self._log_device(cat, w.device_name(inst) or "Virtual network adapter", "Software", "", inst,
                                 inst, "logged", INFO, "Virtual network adapter added (VPN/VM software)")
            return
        if self._suppress.get(inst, 0) > now:
            return
        root = w.physical_root(inst)
        if root in self._session_allowed or root in self.settings.get("guard_trusted", []):
            return
        if now - self._recent.get((root, cat), 0) < GROUP_WINDOW:
            return
        self._recent[(root, cat)] = now
        name = w.device_name(inst) or w.device_name(root) or w.CATEGORY_LABELS[cat]
        rbus = w.bus_of(root)
        bus = "Bluetooth" if rbus.startswith("BTH") else ("Thunderbolt/PCIe" if rbus in ("PCI", "THUNDERBOLT", "USB4")
                                                          else ("USB" if rbus == "USB" else rbus.title()))
        vp = w.vid_pid(root) or w.vid_pid(inst)
        self._check_combo(root, cat, name, vp)
        self.handle(cat, name, bus, vp, inst, root)

    def handle(self, cat, name, bus, vp, inst, root):
        label = w.CATEGORY_LABELS.get(cat, cat)
        blocked = [b for b in self.settings.get("guard_blocked", []) if vp and b.get("vidpid") == vp]
        if blocked:
            ok = self.demo or w.set_device_enabled(root, False, persist=True)
            self._log_device(cat, name, bus, vp, inst, root, "blocked", ALERT,
                             f"Blocked {label.lower()} plugged in again — disabled on sight"
                             + ("" if ok else " (disable FAILED — unplug it)"))
            return
        pol = self.policy(cat)
        if pol == "log":
            self._log_device(cat, name, bus, vp, inst, root, "allowed", INFO, f"{label} connected")
        elif pol == "alert":
            self._log_device(cat, name, bus, vp, inst, root, "allowed", WARN, f"New {label.lower()} connected")
        elif pol == "block":
            ok = self.demo or w.set_device_enabled(inst, False, persist=True)
            self._log_device(cat, name, bus, vp, inst, root, "blocked" if ok else "block failed", WARN,
                             f"{label} blocked by policy")
        elif cat == "keyboard":
            self._kb_root = root
            self._log_device(cat, name, bus, vp, inst, root, "typing frozen", ALERT,
                             "New keyboard — typing frozen until you confirm")
            self.guard.lock(f"New keyboard: {name}" + (f" ({vp})" if vp else ""))
        else:
            ok = self.demo or w.set_device_enabled(inst, False)
            rec = self._log_device(cat, name, bus, vp, inst, root, "held" if ok else "hold failed", WARN,
                                   f"New {label.lower()} is on hold until you allow it")
            if ok:
                self.pending[rec["id"]] = rec
                self.pending_changed.emit(list(self.pending.values()))

    def _check_combo(self, root, cat, name, vp):
        now = time.time()
        g = self._groups.get(root)
        if not g or now - g["t"] > 15:
            g = self._groups[root] = {"t": now, "cats": set(), "flagged": False}
        g["cats"].add(cat)
        if not g["flagged"] and "keyboard" in g["cats"] and g["cats"] & BADUSB_COMBOS:
            g["flagged"] = True
            kinds = ", ".join(sorted(w.CATEGORY_LABELS[c].lower() for c in g["cats"]))
            self.event.emit(ev(ALERT, "One device is pretending to be several things",
                               f"'{name}' ({vp or 'unknown ID'}) showed up as: {kinds}.",
                               "Real flash drives and network adapters don't also act as keyboards. "
                               "This is the classic BadUSB / malicious-cable pattern.",
                               "Unplug it. Use Block on the keyboard prompt if it's still connected."))

    # ------------------------------------------------------------ approve / block
    def allow(self, rec_id, always=False):
        rec = self.pending.pop(rec_id, None)
        if not rec:
            return
        self._suppress[rec["instance"]] = time.time() + 15
        self._session_allowed.add(rec["root"])
        if always and rec["category"] != "keyboard":
            self.settings.setdefault("guard_trusted", []).append(rec["root"])
            storage.save_settings(self.settings)
        ok = self.demo or w.set_device_enabled(rec["instance"], True)
        rec["action"] = ("allowed (always)" if always else "allowed by you") if ok else "enable failed"
        self.device_logged.emit(rec)
        self.event.emit(ev(INFO, f"Allowed {rec['name']}", f"{w.CATEGORY_LABELS[rec['category']]} enabled."))
        self.pending_changed.emit(list(self.pending.values()))

    def block(self, rec_id):
        rec = self.pending.pop(rec_id, None)
        if not rec:
            return
        self._block_root(rec)
        self.pending_changed.emit(list(self.pending.values()))

    def _block_root(self, rec):
        ok = self.demo or w.set_device_enabled(rec["root"], False, persist=True)
        if rec.get("vidpid"):
            bl = self.settings.setdefault("guard_blocked", [])
            if not any(b["vidpid"] == rec["vidpid"] for b in bl):
                bl.append({"vidpid": rec["vidpid"], "name": rec["name"], "category": rec["category"]})
                storage.save_settings(self.settings)
        rec["action"] = "blocked by you" if ok else "block failed — unplug it"
        self.device_logged.emit(rec)
        self.event.emit(ev(ALERT if not ok else WARN, f"Blocked {rec['name']}",
                           "Device disabled and remembered." if ok else "Couldn't disable it. Unplug it now."))

    def unblock(self, vidpid):
        self.settings["guard_blocked"] = [b for b in self.settings.get("guard_blocked", []) if b["vidpid"] != vidpid]
        storage.save_settings(self.settings)

    def _log_device(self, cat, name, bus, vp, inst, root, action, level, title):
        rec = {"id": next(_ids), "time": time.time(), "category": cat, "name": name, "bus": bus,
               "vidpid": vp, "instance": inst, "root": root, "action": action, "level": level}
        self.devices.append(rec)
        self.devices[:] = self.devices[-400:]
        self.device_logged.emit(rec)
        self.event.emit(ev(level, title, f"{name}" + (f" [{vp}]" if vp else "") + f" via {bus}",
                           POLICY_HELP.get(cat, ""),
                           "If you didn't just plug this in, unplug it and click Block."
                           if level != INFO else ""))
        return rec

    # ------------------------------------------------------------ keyboard guard
    def _on_lock(self, locked, reason, code):
        if locked and reason.startswith("Inhumanly"):
            self.event.emit(ev(ALERT, "Robot-speed typing — keyboard frozen",
                               "Keystrokes arrived faster than a human can type.",
                               "This is how Rubber Ducky-style devices type their attack.",
                               "Type the on-screen code to unlock. If you didn't do that typing, unplug "
                               "whatever you just connected."))
        self.kb_locked.emit(locked, reason, code)

    def _unlocked(self, how):
        if self._kb_root:
            self._session_allowed.add(self._kb_root)
        self._kb_root = ""
        self.event.emit(ev(INFO, "Keyboard unlocked", how + "."))

    def kb_allow(self):
        self._unlocked("Unlocked with a mouse click")
        self.guard.unlock()

    def kb_block(self):
        if self._kb_root:
            rec = next((d for d in reversed(self.devices) if d["root"] == self._kb_root), None)
            if rec:
                self._block_root(rec)
        else:
            self.event.emit(ev(WARN, "Speed-trap lock released",
                               "No single device to disable. Unplug anything you don't trust."))
        self._kb_root = ""
        self.guard.unlock()

    # ------------------------------------------------------------ drives
    def _volume_letter_arrived(self, L):
        root = f"{L}:\\"
        guid = w.get_volume_guid(root)
        if not guid:
            return
        if guid in self.drives:
            d = self.drives[guid]
            if d.status not in ("released", "removed", "in place"):
                w.delete_mount_point(root)
            return
        portable, info = w.is_portable_volume(guid, root)
        if not portable:
            return
        label, fs = w.volume_label(root)
        d = self._new_drive(guid, L, info, label, fs)
        pol = self.policy("storage")
        if pol == "block":
            w.delete_mount_point(root)
            d.status = "error"
            self.drive_changed.emit(d)
            self.event.emit(ev(WARN, "Drive blocked by policy", d.title + " was left unmounted."))
            return
        if pol in ("log", "alert"):
            d.status = "in place"
            self.event.emit(ev(INFO if pol == "log" else WARN, "Drive connected", d.title + " (scanning in place)"))
            self._start_scan(d, root)
            return
        if not w.delete_mount_point(root):
            self.event.emit(ev(WARN, "Couldn't quarantine drive", f"Scanning {d.title} in place instead."))
            d.status = "in place"
            self._start_scan(d, root)
            return
        self._quarantine(d)

    def _volume_iface_arrived(self, path):
        guid = w.get_volume_guid(path)
        if not guid:
            return
        self._iface_to_guid[path.lower()] = guid
        if guid in self.drives:
            return
        letters = [p[0] for p in w.get_volume_paths(guid) if len(p) == 3 and p[1] == ":"]
        if letters:
            self._volume_letter_arrived(letters[0])
            return
        portable, info = w.is_portable_volume(guid)
        if portable and self.policy("storage") == "ask":
            self._quarantine(self._new_drive(guid, None, info, "", ""))

    def _new_drive(self, guid, letter, info, label, fs):
        d = Drive(vol_guid=guid, letter=letter, label=label, fs=fs, vendor=info.get("vendor", ""),
                  product=info.get("product", ""), bus=w.BUS_NAMES.get(info.get("bus"), "Removable"))
        self.drives[guid] = d
        return d

    def _quarantine(self, d):
        qpath = os.path.join(quarantine_root(), f"drive{d.id}")
        os.makedirs(qpath, exist_ok=True)
        if not w.set_mount_point(qpath, d.vol_guid):
            d.status = "error"
            self.drive_changed.emit(d)
            self.event.emit(ev(WARN, "Quarantine failed", f"Couldn't mount {d.title} into quarantine."))
            return
        d.qpath = qpath
        if not d.label:
            d.label, d.fs = w.volume_label(qpath + "\\")
        self.event.emit(ev(INFO, "Drive quarantined",
                           f"{d.bus} drive '{d.title}' has no drive letter until it's scanned."))
        self._start_scan(d, qpath)

    def _start_scan(self, d, path):
        in_place = d.status == "in place"
        d.status = "scanning"
        d.cancel.clear()
        self.drive_changed.emit(d)

        def work():
            def prog(n):
                if n >= 0:
                    d.files = n
                self.drive_changed.emit(d)
            res = filescan.full_scan(path, rules_dir(), use_defender=self.settings.get("guard_defender", True),
                                     cancel=d.cancel, progress=prog)
            self._scan_done(d, res, in_place)
        threading.Thread(target=work, daemon=True).start()

    def _scan_done(self, d, res, in_place=False):
        if res.cancelled or d.status == "removed":
            return
        d.files = res.files_scanned
        d.findings = [f.to_text() for f in res.findings] + [f"[DEFENDER] {t}" for t in res.defender_threats]
        d.defender = res.defender
        d.status = res.verdict
        if in_place and d.status == "clean":
            d.status = "released"
        self.drive_changed.emit(d)
        extra = " (stopped at file limit)" if res.truncated else ""
        details = "\n".join(d.findings[:15])
        if d.status in ("clean", "released"):
            self.event.emit(ev(INFO, "Drive scanned clean",
                               f"{d.title}: {d.files} files, nothing found. Defender: {d.defender}.{extra}"))
        elif d.status == "suspicious":
            self.event.emit(ev(WARN, "Drive has executables",
                               f"{d.title}: {len(d.findings)} things worth a look.{extra}", details,
                               "Review the findings. Release it only if you expect those programs."))
        else:
            self.event.emit(ev(ALERT, "Dangerous drive",
                               f"{d.title}: {len(d.findings)} red flags. Defender: {d.defender}.", details,
                               "Leave it quarantined and unplug it. Don't open files from it."))

    def rescan(self, drive_id):
        d = self._by_id(drive_id)
        if d and d.status not in ("scanning", "removed"):
            self._start_scan(d, d.qpath or f"{d.letter}:\\")

    def release(self, drive_id):
        d = self._by_id(drive_id)
        if not d or d.status in ("scanning", "released", "removed"):
            return
        if not self.demo:
            if d.qpath:
                self._unmount_q(d)
            if not self._assign_letter(d):
                d.status = "error"
                self.drive_changed.emit(d)
                self.event.emit(ev(WARN, "Release failed", f"Couldn't give {d.title} a drive letter."))
                return
        d.status = "released"
        self.drive_changed.emit(d)
        self.event.emit(ev(INFO, "Drive released", f"{d.title} is mounted normally."))

    def scan_connected(self):
        if self.demo:
            self.demo_drive()
            return
        found = 0
        for L in sorted(w.used_letters()):
            root = f"{L}:\\"
            guid = w.get_volume_guid(root)
            if not guid or guid in self.drives:
                continue
            portable, info = w.is_portable_volume(guid, root)
            if portable:
                found += 1
                label, fs = w.volume_label(root)
                d = self._new_drive(guid, L, info, label, fs)
                d.status = "in place"
                self._start_scan(d, root)
        if not found:
            self.event.emit(ev(INFO, "Nothing to scan", "No unscanned USB/SD drives are plugged in."))

    def forget(self, drive_id):
        d = self._by_id(drive_id)
        if d and d.status in ("removed", "released", "error"):
            self.drives.pop(d.vol_guid, None)

    def _assign_letter(self, d):
        if any(len(p) == 3 for p in w.get_volume_paths(d.vol_guid)):
            return True
        L = w.free_letter(d.letter)
        if L and w.set_mount_point(f"{L}:\\", d.vol_guid):
            d.letter = L
            return True
        return False

    def _unmount_q(self, d):
        if d.qpath:
            w.delete_mount_point(d.qpath)
            try:
                os.rmdir(d.qpath)
            except OSError:
                pass
            d.qpath = None

    def _drive_removed(self, d):
        d.cancel.set()
        self._unmount_q(d)
        d.status = "removed"
        self.drive_changed.emit(d)

    def _by_id(self, drive_id):
        return next((d for d in self.drives.values() if d.id == drive_id), None)

    # ------------------------------------------------------------ status / demo
    def summary(self):
        bad = [d for d in self.drives.values() if d.status == "dangerous"]
        if self.guard.locked or bad:
            return ALERT
        if self.pending or any(d.status == "suspicious" for d in self.drives.values()):
            return WARN
        return "ok"

    def demo_drive(self, outcome=None):
        fake = f"\\\\?\\Volume{{demo-{random.randint(1000, 9999)}}}\\"
        d = self._new_drive(fake, random.choice("EFGH"), {"vendor": random.choice(["SanDisk", "Kingston", "PNY"]),
                                                           "product": "Cruzer", "bus": w.BUS_USB}, "", "FAT32")
        d.status = "scanning"
        self.drive_changed.emit(d)
        outcome = outcome or random.choice(["clean", "suspicious", "dangerous"])

        def finish():
            res = filescan.ScanResult(files_scanned=random.randint(40, 900), defender="clean")
            if outcome == "suspicious":
                res.findings.append(filescan.Finding("medium", f"{d.letter}:\\tools\\setup.exe", "Executable/script (.exe)"))
            if outcome == "dangerous":
                res.findings.append(filescan.Finding("high", f"{d.letter}:\\Photos.lnk", "Shortcut runs cmd.exe, powershell"))
                res.findings.append(filescan.Finding("high", f"{d.letter}:\\invoice.pdf.exe", "Double extension (.pdf.exe)"))
                res.defender = "threats"
            self._scan_done(d, res)
        QTimer.singleShot(1800, finish)

    def demo_device(self, cat):
        names = {"keyboard": ("HID Keyboard Device", "05AC:021E"), "network": ("ASIX AX88179 USB 3.0 Gigabit Ethernet", "0B95:1790"),
                 "phone": ("Galaxy S24", "04E8:6860"), "thunderbolt": ("Thunderbolt Dock", "8086:15EF"),
                 "bluetooth": ("Unknown Bluetooth Keyboard", "")}
        name, vp = names.get(cat, ("USB device", "1234:5678"))
        root = f"USB\\VID_{vp[:4]}&PID_{vp[5:]}\\DEMO{random.randint(1, 999)}"
        bus = "Bluetooth" if cat == "bluetooth" else ("Thunderbolt/PCIe" if cat == "thunderbolt" else "USB")
        self.handle(cat, name, bus, vp, root + "\\FN", root)

    def demo_badusb(self):
        root = "USB\\VID_1D6B&PID_0104\\OMGCABLE"
        for cat, name in (("storage", "Mass Storage"), ("keyboard", "HID Keyboard Device")):
            self._check_combo(root, cat, "Generic USB Device", "1D6B:0104")
        self._kb_root = root
        self._log_device("keyboard", "HID Keyboard Device", "USB", "1D6B:0104", root + "\\KB", root,
                         "typing frozen", ALERT, "New keyboard — typing frozen until you confirm")
        self.guard.lock("New keyboard: HID Keyboard Device (1D6B:0104)")
