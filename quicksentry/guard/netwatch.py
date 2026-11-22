"""Connection watch: who is listening, who is connecting in, and who touched the firewall.

collect()  -> reads the live tables (Windows API + registry)
Watch.step(snapshot) -> pure logic, returns events (easy to test with fake data)
"""
from __future__ import annotations

import ctypes
import ipaddress
import socket
import subprocess
import sys
import time

IS_WINDOWS = sys.platform == "win32"
INFO, WARN, ALERT = "info", "warn", "alert"

TCP_LISTEN, TCP_ESTABLISHED = 2, 5
REMOTE_ADMIN = {3389: "Remote Desktop", 5985: "WinRM (remote PowerShell)", 5986: "WinRM over HTTPS",
                22: "SSH", 5900: "VNC", 5938: "TeamViewer", 7070: "AnyDesk"}
FILE_RPC = {445: "SMB file sharing", 139: "NetBIOS file sharing", 135: "RPC"}
NOISY_UDP = {53, 67, 68, 123, 137, 138, 500, 1900, 3702, 4500, 5050, 5353, 5355}
SYSTEM_PROCS = {"system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "spoolsv.exe"}
FW_KEY = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
FW_PROFILES = {"DomainProfile": "Domain", "StandardProfile": "Private", "PublicProfile": "Public"}
FW_POLICY_PROFILES = {"DomainProfile": "Domain", "PrivateProfile": "Private", "PublicProfile": "Public"}
OWN_RULE_PREFIX = "QuickSentry block"


def ev(level, title, message, details="", action="", **extra):
    e = {"time": time.time(), "level": level, "title": title, "message": message,
         "details": details, "action": action, "source": "connections"}
    e.update(extra)
    return e


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def is_unspecified(ip: str) -> bool:
    return ip in ("0.0.0.0", "::")


def service_name(port: int) -> str:
    return REMOTE_ADMIN.get(port) or FILE_RPC.get(port) or f"port {port}"


# ======================================================================= collection
if IS_WINDOWS:
    from ctypes import wintypes

    _iphlp = ctypes.WinDLL("iphlpapi")
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _iphlp.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                                           wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    _iphlp.GetExtendedUdpTable.argtypes = _iphlp.GetExtendedTcpTable.argtypes
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                ctypes.POINTER(wintypes.DWORD)]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

    class _TCP4(ctypes.Structure):
        _fields_ = [("state", wintypes.DWORD), ("laddr", wintypes.DWORD), ("lport", wintypes.DWORD),
                    ("raddr", wintypes.DWORD), ("rport", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class _TCP6(ctypes.Structure):
        _fields_ = [("laddr", ctypes.c_ubyte * 16), ("lscope", wintypes.DWORD), ("lport", wintypes.DWORD),
                    ("raddr", ctypes.c_ubyte * 16), ("rscope", wintypes.DWORD), ("rport", wintypes.DWORD),
                    ("state", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class _UDP4(ctypes.Structure):
        _fields_ = [("laddr", wintypes.DWORD), ("lport", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class _UDP6(ctypes.Structure):
        _fields_ = [("laddr", ctypes.c_ubyte * 16), ("lscope", wintypes.DWORD), ("lport", wintypes.DWORD),
                    ("pid", wintypes.DWORD)]


def _table(fn, af, cls, row_t):
    size = wintypes.DWORD(0)
    fn(None, ctypes.byref(size), False, af, cls, 0)
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = wintypes.DWORD(len(buf))
        if fn(buf, ctypes.byref(size), False, af, cls, 0) == 0:
            n = ctypes.c_ulong.from_buffer(buf).value
            off = ctypes.sizeof(ctypes.c_ulong)
            arr = (row_t * n).from_buffer(buf, off)
            return list(arr)
    return []


def _ip4(dw):
    return socket.inet_ntoa(dw.to_bytes(4, "little"))


def _ip6(b):
    return socket.inet_ntop(socket.AF_INET6, bytes(b))


def _port(dw):
    return socket.ntohs(dw & 0xFFFF)


def tcp_rows():
    if not IS_WINDOWS:
        return []
    rows = []
    for r in _table(_iphlp.GetExtendedTcpTable, socket.AF_INET, 5, _TCP4):
        rows.append({"proto": "TCP", "laddr": _ip4(r.laddr), "lport": _port(r.lport), "raddr": _ip4(r.raddr),
                     "rport": _port(r.rport), "state": r.state, "pid": r.pid})
    for r in _table(_iphlp.GetExtendedTcpTable, 23, 5, _TCP6):
        rows.append({"proto": "TCP", "laddr": _ip6(r.laddr), "lport": _port(r.lport), "raddr": _ip6(r.raddr),
                     "rport": _port(r.rport), "state": r.state, "pid": r.pid})
    return rows


def udp_rows():
    if not IS_WINDOWS:
        return []
    rows = [{"proto": "UDP", "laddr": _ip4(r.laddr), "lport": _port(r.lport), "pid": r.pid}
            for r in _table(_iphlp.GetExtendedUdpTable, socket.AF_INET, 1, _UDP4)]
    rows += [{"proto": "UDP", "laddr": _ip6(r.laddr), "lport": _port(r.lport), "pid": r.pid}
             for r in _table(_iphlp.GetExtendedUdpTable, 23, 1, _UDP6)]
    return rows


_proc_cache: dict[int, tuple[float, str]] = {}


def proc_path(pid: int) -> str:
    if pid == 0:
        return "System Idle"
    if pid == 4:
        return "System"
    hit = _proc_cache.get(pid)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    path = ""
    if IS_WINDOWS:
        h = _k32.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
        if h:
            buf = ctypes.create_unicode_buffer(1024)
            n = wintypes.DWORD(1024)
            if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                path = buf.value
            _k32.CloseHandle(h)
    path = path or f"pid {pid}"
    _proc_cache[pid] = (time.time(), path)
    return path


def proc_name(pid: int) -> str:
    p = proc_path(pid)
    return p.replace("/", "\\").rsplit("\\", 1)[-1]


def firewall_rules() -> dict:
    if not IS_WINDOWS:
        return {}
    import winreg
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, FW_KEY + r"\FirewallRules") as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = str(data)
                i += 1
    except OSError:
        pass
    return out


def firewall_profiles() -> dict:
    """Effective on/off per profile (Group Policy wins over local settings)."""
    if not IS_WINDOWS:
        return {}
    import winreg

    def _read(path, value="EnableFirewall"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                return winreg.QueryValueEx(k, value)[0]
        except OSError:
            return None
    out = {}
    for key, label in FW_PROFILES.items():
        v = _read(FW_KEY + "\\" + key)
        out[label] = True if v is None else bool(v)
    for key, label in FW_POLICY_PROFILES.items():
        v = _read(r"SOFTWARE\Policies\Microsoft\WindowsFirewall" + "\\" + key)
        if v is not None:
            out[label] = bool(v)
    return out


def collect(with_firewall=True) -> dict:
    snap = {"tcp": tcp_rows(), "udp": udp_rows(), "time": time.time()}
    if with_firewall:
        snap["rules"] = firewall_rules()
        snap["profiles"] = firewall_profiles()
    return snap


# ======================================================================= logic
def parse_rule(data: str) -> dict:
    out = {}
    for part in data.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = out[k] + "," + v if k in out else v
    return out


def rule_label(r: dict) -> str:
    name = r.get("Name", "?")
    if name.startswith("@"):
        name = r.get("EmbedCtxt") or name
    bits = [name]
    if r.get("App"):
        bits.append(r["App"])
    if r.get("LPort"):
        bits.append(f"port {r['LPort']}")
    return " — ".join(bits)


class Watch:
    def __init__(self, trusted_ips=None, name_of=proc_name, path_of=proc_path):
        self.trusted = set(trusted_ips or [])
        self.name_of, self.path_of = name_of, path_of
        self.listeners: dict[tuple, dict] = {}
        self.sessions: dict[tuple, dict] = {}
        self.fw_changes: list[dict] = []
        self._seen_inbound: set[tuple] = set()
        self._rules: dict | None = None
        self._profiles: dict | None = None
        self._baselined = False

    # -- helpers
    def _listener_key(self, r):
        return (r["proto"], r["laddr"], r["lport"])

    def _is_noise_udp(self, r):
        return r["lport"] in NOISY_UDP or r["lport"] >= 49152

    def step(self, snap: dict) -> list[dict]:
        events = []
        now = snap.get("time", time.time())

        # ---------- listeners
        current = {}
        for r in snap.get("tcp", []):
            if r["state"] == TCP_LISTEN and not is_loopback(r["laddr"]):
                current[self._listener_key(r)] = r
        for r in snap.get("udp", []):
            if not is_loopback(r["laddr"]) and not self._is_noise_udp(r):
                current[self._listener_key(r)] = r
        for key, r in current.items():
            if key in self.listeners:
                continue
            name = self.name_of(r["pid"])
            self.listeners[key] = {**r, "proc": name, "path": self.path_of(r["pid"]), "since": now,
                                   "new": self._baselined}
            if not self._baselined:
                continue
            quiet = (name.lower() in SYSTEM_PROCS and r["lport"] >= 49152)
            where = f"{r['proto']} {r['laddr']}:{r['lport']}"
            events.append(ev(INFO if quiet else WARN, "New program accepting connections",
                             f"{name} is now listening on {where}" +
                             (f" ({service_name(r['lport'])})" if r["lport"] in REMOTE_ADMIN or r["lport"] in FILE_RPC else ""),
                             f"Program: {self.path_of(r['pid'])}\nPID: {r['pid']}\n"
                             "Malware that wants remote control opens a listening port. So do games, "
                             "chat apps, printers and dev tools.",
                             "If you don't recognize the program, block it below and check it with your antivirus.",
                             pid=r["pid"], path=self.path_of(r["pid"])))
        for key in list(self.listeners):
            if key not in current:
                del self.listeners[key]

        # ---------- inbound sessions (established TCP on a port we listen on)
        listen_ports = {(r["lport"], r["pid"]) for r in snap.get("tcp", []) if r["state"] == TCP_LISTEN}
        active = {}
        for r in snap.get("tcp", []):
            if r["state"] != TCP_ESTABLISHED or is_loopback(r["raddr"]) or r["raddr"] == r["laddr"]:
                continue
            if (r["lport"], r["pid"]) not in listen_ports:
                continue
            key = (r["raddr"].split("%")[0], r["lport"])
            active[key] = r
        for key, r in active.items():
            if key not in self.sessions:
                self.sessions[key] = {**r, "proc": self.name_of(r["pid"]), "service": service_name(r["lport"]),
                                      "since": now, "trusted": key[0] in self.trusted}
            if key in self._seen_inbound:
                continue
            self._seen_inbound.add(key)
            if not self._baselined:
                continue
            ip, port = key
            svc = service_name(port)
            if ip in self.trusted:
                level = INFO
            elif port in REMOTE_ADMIN:
                level = ALERT
            else:
                level = WARN
            events.append(ev(level, f"Inbound {svc} connection",
                             f"{ip} connected to {self.name_of(r['pid'])} on port {port}",
                             "Someone on the network opened a session INTO this computer." +
                             (" Remote-control protocols are how attackers take over machines."
                              if port in REMOTE_ADMIN else
                              " On managed networks this is often SCCM, file shares or IT tools."),
                             "If it's IT or a server you know, click Trust. Otherwise block the address.",
                             remote_ip=ip, pid=r["pid"], path=self.path_of(r["pid"])))
        for key in list(self.sessions):
            if key not in active:
                del self.sessions[key]

        # ---------- firewall
        if "rules" in snap:
            events += self._firewall(snap["rules"], snap.get("profiles", {}), now)

        self._baselined = True
        return events

    def _firewall(self, rules, profiles, now):
        events = []
        for prof, on in profiles.items():
            was = (self._profiles or {}).get(prof, True)
            if not on and (was or self._profiles is None):
                events.append(ev(ALERT, f"Windows Firewall is OFF ({prof} profile)",
                                 f"The {prof} firewall profile is turned off.",
                                 "With the firewall off, every listening program is reachable from the network. "
                                 "Malware often turns it off first.",
                                 "Turn it back on: Windows Security > Firewall & network protection."))
            elif on and not was:
                events.append(ev(INFO, f"Windows Firewall back on ({prof})", "Firewall profile re-enabled."))
        self._profiles = dict(profiles)

        if self._rules is None:
            self._rules = dict(rules)
            return events
        for rid, data in rules.items():
            old = self._rules.get(rid)
            if old == data:
                continue
            r = parse_rule(data)
            if r.get("Name", "").startswith(OWN_RULE_PREFIX):
                continue
            opens = r.get("Action") == "Allow" and r.get("Dir") == "In" and r.get("Active") == "TRUE"
            kind = "added" if old is None else "changed"
            rec = {"time": now, "kind": kind, "label": rule_label(r), "opens": opens}
            self.fw_changes.append(rec)
            if opens:
                events.append(ev(WARN, f"Firewall rule {kind}: inbound ALLOW",
                                 rule_label(r),
                                 "A rule now lets the network reach this computer. Installers add these "
                                 "legitimately; malware adds them to open a door.\n\n" + data[:400],
                                 "If you didn't just install or change something, remove the rule in "
                                 "Windows Defender Firewall > Advanced settings."))
            else:
                events.append(ev(INFO, f"Firewall rule {kind}", rule_label(r)))
        for rid in set(self._rules) - set(rules):
            r = parse_rule(self._rules[rid])
            self.fw_changes.append({"time": now, "kind": "removed", "label": rule_label(r), "opens": False})
            events.append(ev(INFO, "Firewall rule removed", rule_label(r)))
        self.fw_changes[:] = self.fw_changes[-300:]
        self._rules = dict(rules)
        return events

    def summary(self):
        if any(not s["trusted"] and s["lport"] in REMOTE_ADMIN for s in self.sessions.values()):
            return ALERT
        if self._profiles and not all(self._profiles.values()):
            return ALERT
        if any(l.get("new") for l in self.listeners.values()):
            return WARN
        return "ok"


class View:
    """Read-only copy of a Watch for the UI thread (the worker keeps mutating the original)."""

    def __init__(self, w: "Watch | None" = None):
        self.listeners = {k: dict(v) for k, v in (w.listeners if w else {}).items()}
        self.sessions = {k: dict(v) for k, v in (w.sessions if w else {}).items()}
        self.fw_changes = list(w.fw_changes) if w else []
        self._profiles = dict(w._profiles) if w and w._profiles is not None else None
        self.trusted = set(w.trusted) if w else set()

    summary = Watch.summary


# ======================================================================= actions
def _netsh(args):
    try:
        cp = subprocess.run(["netsh", "advfirewall", "firewall"] + args, capture_output=True, text=True,
                            timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return cp.returncode == 0, (cp.stdout or cp.stderr).strip()
    except Exception as e:
        return False, str(e)


def block_ip(ip: str):
    ip = str(ipaddress.ip_address(ip.split("%")[0]))      # validates; raises on junk
    return _netsh(["add", "rule", f"name={OWN_RULE_PREFIX} {ip}", "dir=in", "action=block", f"remoteip={ip}"])


def block_program(path: str):
    import os
    if not os.path.isabs(path) or not os.path.isfile(path):
        return False, "Program path not available (protected process?)"
    exe = os.path.basename(path)
    return _netsh(["add", "rule", f"name={OWN_RULE_PREFIX} {exe}", "dir=in", "action=block", f"program={path}"])
