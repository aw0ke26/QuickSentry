"""Tests for the v3 guard logic (no Windows needed). Run: python tests/test_guard.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QUICKSENTRY_DATA", tempfile.mkdtemp())

from quicksentry.guard import filescan, netwatch, win32dev  # noqa: E402

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("FAIL:", msg)


# ---------------------------------------------------------------- device classification
iid = win32dev.interface_path_to_instance_id(
    r"\\?\HID#VID_05AC&PID_021E&MI_00#7&2b5f3f8&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}")
check(iid == r"HID\VID_05AC&PID_021E&MI_00\7&2B5F3F8&0&0000", f"instance id: {iid}")
check(win32dev.vid_pid(iid) == "05AC:021E", "vid:pid")
check(win32dev.categorize(win32dev.GUID_KEYBOARD, iid) == "keyboard", "keyboard category")
check(win32dev.categorize(win32dev.GUID_NET, r"USB\VID_0B95&PID_1790\1") == "network", "nic category")
check(win32dev.categorize("deadbeef-0000-0000-0000-000000000000", r"BTHENUM\{X}\Y") == "bluetooth", "bt by bus")
check(win32dev.categorize("deadbeef-0000-0000-0000-000000000000", r"PCI\VEN_8086&DEV_15EF\Z") == "thunderbolt", "pci")
check(win32dev.categorize(win32dev.GUID_USB_HUB, r"USB\ROOT_HUB30\1") is None, "hubs ignored")
check(win32dev.categorize("deadbeef-0000-0000-0000-000000000000", r"ACPI\PNP0C0A\1") is None, "acpi ignored")
check(win32dev.is_software(r"SWD\MSRRAS\MS_NDISWANIP"), "software bus")

# ---------------------------------------------------------------- file scan heuristics
d = tempfile.mkdtemp()
open(os.path.join(d, "autorun.inf"), "w").write("[autorun]\nopen=evil.exe\n")
open(os.path.join(d, "invoice.pdf.exe"), "wb").write(b"MZ")
open(os.path.join(d, "holiday.jpg"), "wb").write(b"MZ\x90")
open(os.path.join(d, "notes.txt"), "w").write("hi")
r = filescan.heuristic_scan(d)
check(r.verdict == "dangerous" and len(r.findings) == 3, f"filescan findings: {[f.reason for f in r.findings]}")
check(filescan.heuristic_scan(tempfile.mkdtemp()).verdict == "clean", "empty drive clean")

# ---------------------------------------------------------------- connection watch
def tcp(l, lp, r="0.0.0.0", rp=0, state=netwatch.TCP_LISTEN, pid=100):
    return {"proto": "TCP", "laddr": l, "lport": lp, "raddr": r, "rport": rp, "state": state, "pid": pid}


names = {100: "svchost.exe", 200: "evil.exe", 300: "TermService.exe"}
w = netwatch.Watch(trusted_ips=["10.0.0.5"], name_of=lambda p: names.get(p, "x"), path_of=lambda p: "C:\\x.exe")
base = {"tcp": [tcp("0.0.0.0", 135), tcp("0.0.0.0", 3389, pid=300), tcp("127.0.0.1", 9000, pid=200)],
        "udp": [], "rules": {"r1": "v2.30|Action=Allow|Active=TRUE|Dir=In|Name=Core|"},
        "profiles": {"Domain": True, "Private": True, "Public": True}}
check(w.step(base) == [], "baseline is silent")
snap = dict(base, tcp=base["tcp"] + [tcp("0.0.0.0", 4444, pid=200)])
e = w.step(snap)
check(len(e) == 1 and e[0]["level"] == "warn" and "4444" in e[0]["message"], f"new listener: {e}")
check(w.step(snap) == [], "no repeat")
snap2 = dict(snap, tcp=snap["tcp"] + [tcp("192.168.1.20", 3389, "192.168.1.66", 51000, netwatch.TCP_ESTABLISHED, 300),
                                      tcp("192.168.1.20", 135, "10.0.0.5", 50000, netwatch.TCP_ESTABLISHED, 100)])
e = w.step(snap2)
lv = sorted((x["title"], x["level"]) for x in e)
check(("Inbound Remote Desktop connection", "alert") in lv and ("Inbound RPC connection", "info") in lv, f"inbound: {lv}")
check(w.summary() == "alert", "summary alert during RDP")
snap3 = dict(snap2, rules={**base["rules"], "r2": "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\\evil.exe|Name=Updater|"},
             profiles={"Domain": True, "Private": True, "Public": False})
e = w.step(snap3)
titles = [x["title"] for x in e]
check("Windows Firewall is OFF (Public profile)" in titles, f"fw off: {titles}")
check("Firewall rule added: inbound ALLOW" in titles, f"fw rule: {titles}")
snap4 = dict(snap3, rules={**snap3["rules"], "r3": "v2.30|Action=Block|Dir=In|Name=QuickSentry block 1.2.3.4|"})
check(not any("rule" in x["title"].lower() for x in w.step(snap4)), "own rules ignored")
check(netwatch.parse_rule("A=1|B=2|B=3|")["B"] == "2,3", "rule parse multi")
try:
    netwatch.block_ip("1.2.3.4; rm -rf")
    check(False, "block_ip must reject junk")
except ValueError:
    pass

# ---------------------------------------------------------------- uninstall cleanup
try:
    from quicksentry.guard.hardware import cleanup_system, quarantine_root
    os.makedirs(os.path.join(quarantine_root(), "drive1"), exist_ok=True)
    keep = os.path.join(quarantine_root(), "drive2")
    os.makedirs(keep, exist_ok=True)
    open(os.path.join(keep, "file-on-usb.txt"), "w").write("must survive")
    cleanup_system()
    check(not os.path.exists(os.path.join(quarantine_root(), "drive1")), "empty quarantine dir removed")
    check(os.path.exists(os.path.join(keep, "file-on-usb.txt")), "cleanup never deletes files inside quarantine")
except ImportError as e:   # PySide6 not installed
    print("skip cleanup test:", e)

print("ALL OK" if not FAILS else f"{len(FAILS)} FAILED")
sys.exit(1 if FAILS else 0)
