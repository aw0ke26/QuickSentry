"""Thin Windows API layer (ctypes). Every function has a subprocess fallback so a
struct/API problem degrades to slower-but-working instead of crashing.

- neighbor_table(): IPv4 + IPv6 neighbor cache (GetIpNetTable2), incl. IsRouter flag
- best_route():     default gateway + interface for internet traffic (GetBestRoute)
- icmp_probe():     single ICMP echo with a chosen TTL (IcmpSendEcho) -> ping/traceroute
"""

import ctypes
import ipaddress
import re
import socket
import subprocess
import sys

from . import oui

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# ICMP status codes
IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013
IP_TTL_EXPIRED_REASSEM = 11014

AF_INET, AF_INET6 = 2, 23


def run(cmd, timeout=15):
    """Run a command hidden, return stdout ('' on failure)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                              timeout=timeout, creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def ip_to_dword(ip):
    return int.from_bytes(socket.inet_aton(ip), "little")


def dword_to_ip(v):
    return socket.inet_ntoa(int(v).to_bytes(4, "little"))


# --------------------------------------------------------------------------
# Structures (explicit-width types so sizes match Windows x64)
# --------------------------------------------------------------------------
c_u8, c_u16, c_u32, c_u64 = ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint32, ctypes.c_uint64


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [("sin_family", c_u16), ("sin_port", c_u16),
                ("sin_addr", c_u8 * 4), ("sin_zero", c_u8 * 8)]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [("sin6_family", c_u16), ("sin6_port", c_u16), ("sin6_flowinfo", c_u32),
                ("sin6_addr", c_u8 * 16), ("sin6_scope_id", c_u32)]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [("Ipv4", SOCKADDR_IN), ("Ipv6", SOCKADDR_IN6), ("si_family", c_u16)]


class MIB_IPNET_ROW2(ctypes.Structure):
    _fields_ = [("Address", SOCKADDR_INET), ("InterfaceIndex", c_u32),
                ("InterfaceLuid", c_u64), ("PhysicalAddress", c_u8 * 32),
                ("PhysicalAddressLength", c_u32), ("State", ctypes.c_int),
                ("Flags", c_u8), ("ReachabilityTime", c_u32)]


class MIB_IPNET_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", c_u32), ("Table", MIB_IPNET_ROW2 * 1)]


class MIB_IPFORWARDROW(ctypes.Structure):
    _fields_ = [(n, c_u32) for n in (
        "dwForwardDest", "dwForwardMask", "dwForwardPolicy", "dwForwardNextHop",
        "dwForwardIfIndex", "dwForwardType", "dwForwardProto", "dwForwardAge",
        "dwForwardNextHopAS", "dwForwardMetric1", "dwForwardMetric2",
        "dwForwardMetric3", "dwForwardMetric4", "dwForwardMetric5")]


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", c_u8), ("Tos", c_u8), ("Flags", c_u8),
                ("OptionsSize", c_u8), ("OptionsData", ctypes.c_void_p)]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", c_u32), ("Status", c_u32), ("RoundTripTime", c_u32),
                ("DataSize", c_u16), ("Reserved", c_u16), ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION)]


_ipapi = None


def _api():
    global _ipapi
    if _ipapi is None and IS_WINDOWS:
        _ipapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        _ipapi.IcmpCreateFile.restype = ctypes.c_void_p
        _ipapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        _ipapi.IcmpSendEcho.argtypes = [ctypes.c_void_p, c_u32, ctypes.c_void_p, c_u16,
                                        ctypes.POINTER(IP_OPTION_INFORMATION),
                                        ctypes.c_void_p, c_u32, c_u32]
        _ipapi.IcmpSendEcho.restype = c_u32
        _ipapi.GetIpNetTable2.argtypes = [c_u16, ctypes.POINTER(ctypes.POINTER(MIB_IPNET_TABLE2))]
        _ipapi.GetIpNetTable2.restype = c_u32
        _ipapi.FreeMibTable.argtypes = [ctypes.c_void_p]
        _ipapi.GetBestRoute.argtypes = [c_u32, c_u32, ctypes.POINTER(MIB_IPFORWARDROW)]
        _ipapi.GetBestRoute.restype = c_u32
        _ipapi.ConvertInterfaceIndexToLuid.argtypes = [c_u32, ctypes.POINTER(c_u64)]
        _ipapi.ConvertInterfaceLuidToAlias.argtypes = [ctypes.POINTER(c_u64),
                                                       ctypes.c_wchar_p, ctypes.c_size_t]
    return _ipapi


# --------------------------------------------------------------------------
# Neighbor table
# --------------------------------------------------------------------------
# NL_NEIGHBOR_STATE: 0 Unreachable, 1 Incomplete, 2 Probe, 3 Delay, 4 Stale,
#                    5 Reachable, 6 Permanent
_STATE_NAMES = {2: "probe", 3: "delay", 4: "stale", 5: "reachable", 6: "static"}


def _neighbor_table_api():
    api = _api()
    ptr = ctypes.POINTER(MIB_IPNET_TABLE2)()
    if api.GetIpNetTable2(0, ctypes.byref(ptr)) != 0:
        raise OSError("GetIpNetTable2 failed")
    try:
        n = ptr.contents.NumEntries
        if n > 100000:
            raise OSError("implausible neighbor count")
        rows = ctypes.cast(ctypes.addressof(ptr.contents.Table),
                           ctypes.POINTER(MIB_IPNET_ROW2 * n)).contents
        out = []
        for r in rows:
            if r.State not in _STATE_NAMES:
                continue
            ln = r.PhysicalAddressLength
            if ln != 6:
                continue
            mac = ":".join(f"{b:02x}" for b in r.PhysicalAddress[:6])
            fam = r.Address.si_family
            if fam == AF_INET:
                ip = socket.inet_ntoa(bytes(r.Address.Ipv4.sin_addr))
            elif fam == AF_INET6:
                ip = socket.inet_ntop(socket.AF_INET6, bytes(r.Address.Ipv6.sin6_addr))
            else:
                continue
            out.append({"ip": ip, "mac": mac, "family": 4 if fam == AF_INET else 6,
                        "ifindex": r.InterfaceIndex, "state": _STATE_NAMES[r.State],
                        "is_router": bool(r.Flags & 0x01)})
        return out
    finally:
        api.FreeMibTable(ptr)


_ARP_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)",
                       re.MULTILINE)
_ARP_IFACE = re.compile(r"^Interface:\s*([\d.]+)\s+---\s+0x([0-9a-fA-F]+)", re.MULTILINE)


def parse_arp_a(text):
    """Parse Windows `arp -a` output (fallback path)."""
    out = []
    ifindex = 0
    for line in text.splitlines():
        m = _ARP_IFACE.match(line)
        if m:
            ifindex = int(m.group(2), 16)
            continue
        m = _ARP_LINE.match(line)
        if m:
            out.append({"ip": m.group(1), "mac": oui.normalize(m.group(2)), "family": 4,
                        "ifindex": ifindex,
                        "state": "static" if m.group(3).lower() == "static" else "reachable",
                        "is_router": False})
    return out


def neighbor_table():
    """List of neighbor dicts for IPv4 and IPv6, unusable MACs removed."""
    rows = None
    if IS_WINDOWS:
        try:
            rows = _neighbor_table_api()
        except Exception:
            rows = None
    if rows is None:
        rows = parse_arp_a(run(["arp", "-a"])) if IS_WINDOWS else []
    clean = []
    for r in rows:
        if not oui.is_usable(r["mac"]):
            continue
        try:
            a = ipaddress.ip_address(r["ip"].split("%")[0])
            if a.is_multicast or a.is_unspecified:
                continue
        except ValueError:
            continue
        clean.append(r)
    return clean


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------
def best_route(dest="1.1.1.1"):
    """(gateway_ip, ifindex) for traffic to dest, or (None, None)."""
    if IS_WINDOWS:
        try:
            row = MIB_IPFORWARDROW()
            if _api().GetBestRoute(ip_to_dword(dest), 0, ctypes.byref(row)) == 0:
                gw = dword_to_ip(row.dwForwardNextHop)
                return (gw if gw != "0.0.0.0" else None), row.dwForwardIfIndex
        except Exception:
            pass
        # Fallback: route print
        best = None
        for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+([\d.]+)\s+(\d+)",
                             run(["route", "print", "-4", "0.0.0.0"]), re.MULTILINE):
            if best is None or int(m.group(3)) < best[1]:
                best = (m.group(1), int(m.group(3)))
        return (best[0] if best else None), None
    # Non-Windows (dev/testing only)
    m = re.search(r"default via ([\d.]+)", run(["ip", "route", "show", "default"]))
    return (m.group(1) if m else None), None


def interface_alias(ifindex):
    """'Wi-Fi', 'Ethernet', ... for an interface index."""
    if not (IS_WINDOWS and ifindex):
        return None
    try:
        api = _api()
        luid = c_u64()
        if api.ConvertInterfaceIndexToLuid(ifindex, ctypes.byref(luid)) != 0:
            return None
        buf = ctypes.create_unicode_buffer(257)
        if api.ConvertInterfaceLuidToAlias(ctypes.byref(luid), buf, 257) != 0:
            return None
        return buf.value
    except Exception:
        return None


# --------------------------------------------------------------------------
# ICMP
# --------------------------------------------------------------------------
def _icmp_api(ip, ttl, timeout_ms):
    api = _api()
    h = api.IcmpCreateFile()
    if not h or h == ctypes.c_void_p(-1).value:
        raise OSError("IcmpCreateFile failed")
    try:
        data = b"QSENTRY!" * 4
        opts = IP_OPTION_INFORMATION(Ttl=ttl)
        size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(data) + 8 + 64
        buf = ctypes.create_string_buffer(size)
        n = api.IcmpSendEcho(h, ip_to_dword(ip), data, len(data), ctypes.byref(opts),
                             buf, size, timeout_ms)
        reply = ICMP_ECHO_REPLY.from_buffer_copy(buf)
        if (n == 0 and reply.Address == 0) or reply.Status == IP_REQ_TIMED_OUT:
            return None, None, None
        frm = dword_to_ip(reply.Address) if reply.Address else None
        return reply.Status, frm, reply.RoundTripTime
    finally:
        api.IcmpCloseHandle(h)


_PING_FROM = re.compile(r"(?:Reply from|from)\s+([\d.]+)", re.IGNORECASE)
_PING_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def _icmp_subprocess(ip, ttl, timeout_ms):
    if IS_WINDOWS:
        out = run(["ping", "-n", "1", "-w", str(timeout_ms), "-i", str(ttl), ip],
                  timeout=timeout_ms / 1000 + 5)
    else:
        out = run(["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), "-t", str(ttl), ip],
                  timeout=timeout_ms / 1000 + 5)
    m = _PING_FROM.search(out)
    if not m:
        return None, None, None
    frm = m.group(1).rstrip(":")
    low = out.lower()
    if "ttl expired" in low or "time to live exceeded" in low:
        status = IP_TTL_EXPIRED_TRANSIT
    elif "unreachable" in low:
        status = IP_DEST_HOST_UNREACHABLE
    else:
        status = IP_SUCCESS
    t = _PING_TIME.search(out)
    return status, frm, (float(t.group(1)) if t else None)


_icmp_api_ok = True


def icmp_probe(ip, ttl=128, timeout_ms=1000):
    """Send one ICMP echo. Returns (status, from_ip, rtt_ms); (None, None, None) = no reply.
    status: IP_SUCCESS (dest answered), IP_TTL_EXPIRED_TRANSIT (a hop answered), or other."""
    global _icmp_api_ok
    if IS_WINDOWS and _icmp_api_ok:
        try:
            return _icmp_api(ip, ttl, timeout_ms)
        except Exception:
            _icmp_api_ok = False
    return _icmp_subprocess(ip, ttl, timeout_ms)


def resolve(host):
    """Hostname -> first IPv4, or the input if it is already an IP. None on failure."""
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return None


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------
def is_admin():
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_elevated(exe, args):
    """Run a command as admin (UAC prompt if needed). Returns True if it was launched.
    Note: when a UAC prompt is used we can't see the exit code - verify afterwards."""
    if not IS_WINDOWS:
        return False
    if is_admin():
        run([exe] + list(args))
        return True
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe,
                                             subprocess.list2cmdline(list(args)), None, 0)
    return rc > 32


def message_box(title, text):
    """Native always-on-top warning box (blocking; call from a thread)."""
    if IS_WINDOWS:
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x30 | 0x40000 | 0x1000)


def beep():
    if IS_WINDOWS:
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass


def drive_is_removable(path):
    if not IS_WINDOWS:
        return False
    try:
        import os
        root = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
        return ctypes.windll.kernel32.GetDriveTypeW(root) == 2  # DRIVE_REMOVABLE
    except Exception:
        return False
