"""Ping sweep of an IP range, combined with the ARP table, to list devices and flag
suspicious ones. Hosts that block ping still show up if they answer ARP (same subnet)."""

import concurrent.futures as cf
import ipaddress
import re

from . import oui, winapi
from .pathmon import rdns

MAX_HOSTS = 1024


def parse_targets(spec, local_net=None):
    """'192.168.1.0/24', '10.0.0.10-10.0.0.50', '10.0.0.10-50', '10.0.0.5', or 'local'.
    Returns (list_of_ips, error_message)."""
    spec = (spec or "").strip()
    try:
        if spec.lower() in ("", "local"):
            if local_net is None:
                return [], "Couldn't detect your local subnet."
            net = local_net
            if net.num_addresses > MAX_HOSTS + 2:
                return [], (f"Your subnet ({net}) has more than {MAX_HOSTS} addresses. "
                            f"Enter a smaller range.")
            return [str(h) for h in net.hosts()], None
        if "/" in spec:
            net = ipaddress.IPv4Network(spec, strict=False)
            if net.num_addresses > MAX_HOSTS + 2:
                return [], f"Range too large (max {MAX_HOSTS} addresses)."
            return [str(h) for h in (net.hosts() if net.prefixlen < 31 else net)], None
        m = re.match(r"^([\d.]+)\s*-\s*([\d.]+)$", spec)
        if m:
            start = ipaddress.IPv4Address(m.group(1))
            end_s = m.group(2)
            if "." not in end_s:
                end_s = ".".join(m.group(1).split(".")[:3] + [end_s])
            end = ipaddress.IPv4Address(end_s)
            if end < start:
                return [], "Range end is before range start."
            if int(end) - int(start) + 1 > MAX_HOSTS:
                return [], f"Range too large (max {MAX_HOSTS} addresses)."
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)], None
        return [str(ipaddress.IPv4Address(spec))], None
    except ValueError as e:
        return [], f"Invalid range: {e}"


def sweep(ips, progress=None, cancel=None, my_ip=None, gateway_ip=None, lookup_names=True):
    """Returns list of device dicts. progress(done, total) is called from worker threads."""
    alive = {}
    done = 0
    total = len(ips)

    def ping(ip):
        if cancel is not None and cancel.is_set():
            return ip, None
        st, frm, rtt = winapi.icmp_probe(ip, ttl=128, timeout_ms=700)
        return ip, (rtt if st == winapi.IP_SUCCESS and frm == ip else None)

    with cf.ThreadPoolExecutor(48) as ex:
        for ip, rtt in ex.map(ping, ips):
            done += 1
            if rtt is not None:
                alive[ip] = rtt
            if progress and (done % 8 == 0 or done == total):
                progress(done, total)
    if cancel is not None and cancel.is_set():
        return []

    wanted = set(ips)
    arp = {n["ip"]: n["mac"] for n in winapi.neighbor_table() if n["family"] == 4}
    found = sorted((wanted & (set(alive) | set(arp))),
                   key=lambda s: int(ipaddress.IPv4Address(s)))
    macs = {}
    for ip in found:
        if ip in arp:
            macs.setdefault(arp[ip], []).append(ip)
    rows = []
    names = {}
    if lookup_names:
        with cf.ThreadPoolExecutor(16) as ex:
            names = dict(zip(found, ex.map(rdns, found)))
    for ip in found:
        mac = arp.get(ip, "")
        flags = []
        if ip == my_ip:
            flags.append("This computer")
        if ip == gateway_ip:
            flags.append("Router")
        cat = oui.category(mac) if mac else ""
        if mac and len(macs.get(mac, [])) > 1:
            others = [o for o in macs[mac] if o != ip]
            flags.append("Same MAC as " + ", ".join(others) +
                         (" (ROUTER - possible spoofing)" if gateway_ip in others else ""))
        if cat == "attack_tool":
            flags.append("Known hacking hardware")
        elif cat == "randomized":
            flags.append("Randomized MAC")
        elif cat == "virtual":
            flags.append("Virtual machine")
        elif cat == "sbc":
            flags.append("Raspberry Pi")
        level = "alert" if any("spoofing" in f or "hacking" in f for f in flags) else \
            "warn" if any(f.startswith("Same MAC") for f in flags) else "ok"
        rows.append({"ip": ip, "mac": mac, "vendor": oui.vendor(mac) if mac else "",
                     "name": names.get(ip, ""), "rtt": alive.get(ip),
                     "responds_ping": ip in alive, "flags": flags, "level": level})
    return rows
