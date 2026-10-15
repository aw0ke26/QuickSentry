"""Path monitor: repeated traceroutes to one or more targets, learning the normal path
and flagging new devices in the path, path-length changes, latency jumps, loss and
outages.

Limits (shown in the GUI too): a device that routes traffic (adds a hop) is visible.
A fully transparent inline device (bridge / tap) does not appear in traceroute; only its
side effects (latency, loss) might.
"""

import concurrent.futures as cf
import ipaddress
import socket
import statistics
import time

from . import oui, winapi

OK, INFO, WARN, ALERT = "ok", "info", "warn", "alert"
LEARN_RUNS = 3
_rdns_cache = {}
_rdns_pool = cf.ThreadPoolExecutor(4)


def rdns(ip, timeout=1.5):
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    try:
        name = _rdns_pool.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=timeout)
    except Exception:
        name = ""
    _rdns_cache[ip] = name
    return name


def traceroute(ip, max_hops=30, timeout_ms=1000, probe=None, batch=8):
    """List of hops: {ttl, ip, rtt, reached}. Probes TTLs in parallel batches."""
    probe = probe or winapi.icmp_probe

    def one(ttl):
        for _ in range(2):
            st, frm, rtt = probe(ip, ttl=ttl, timeout_ms=timeout_ms)
            if frm:
                return {"ttl": ttl, "ip": frm, "rtt": rtt,
                        "reached": st == winapi.IP_SUCCESS or frm == ip}
        return {"ttl": ttl, "ip": None, "rtt": None, "reached": False}

    hops = []
    with cf.ThreadPoolExecutor(batch) as ex:
        for start in range(1, max_hops + 1, batch):
            ttls = range(start, min(start + batch, max_hops + 1))
            res = list(ex.map(one, ttls))
            for h in res:
                hops.append(h)
                if h["reached"]:
                    return hops
    return hops


def ping_stats(ip, count=4, timeout_ms=1000, probe=None):
    probe = probe or winapi.icmp_probe
    rtts = []
    for _ in range(count):
        st, frm, rtt = probe(ip, ttl=128, timeout_ms=timeout_ms)
        if st == winapi.IP_SUCCESS and frm:
            rtts.append(rtt or 0)
    loss = 100 * (count - len(rtts)) / count
    return {"loss": loss, "avg": (sum(rtts) / len(rtts)) if rtts else None}


class Target:
    def __init__(self, host):
        self.host = host
        self.ip = None
        self.runs = 0
        self.known = set()            # every hop IP seen while learning / accepted
        self.lengths = set()          # path lengths seen while learning
        self.rtts = []                # dest avg RTT while learning
        self.dest_mac = None          # for targets on the local subnet
        self.hops = []
        self.stats = {}
        self.status = INFO
        self.summary = "Waiting for first run..."
        self.details = ""
        self.ever_reached = False

    def accept_current(self):
        self.known |= {h["ip"] for h in self.hops if h["ip"]}
        reached = [h for h in self.hops if h["reached"]]
        if reached:
            self.lengths.add(reached[-1]["ttl"])
        if self.stats.get("avg") is not None:
            self.rtts.append(self.stats["avg"])
        self.status, self.summary = OK, "Current path accepted as normal."


def run_target(t, gateway_ip=None, local_net=None, neighbors=None, probe=None):
    """Run one measurement for a Target; updates it in place. Returns list of events."""
    events = []
    neighbors = neighbors or {}
    t.ip = winapi.resolve(t.host)
    if not t.ip:
        t.status, t.summary = WARN, f"Can't resolve '{t.host}'."
        return events
    hops = traceroute(t.ip, probe=probe)
    stats = ping_stats(t.ip, probe=probe)
    for h in hops:
        if h["ip"]:
            mac = neighbors.get(h["ip"])
            h["mac"] = mac
            h["vendor"] = oui.vendor(mac) if mac else ""
            h["name"] = rdns(h["ip"])
        else:
            h["mac"] = h["vendor"] = h["name"] = ""
    t.hops, t.stats = hops, stats
    reached = any(h["reached"] for h in hops) or stats["loss"] < 100
    length = next((h["ttl"] for h in hops if h["reached"]), None)
    on_subnet = False
    try:
        on_subnet = local_net is not None and ipaddress.IPv4Address(t.ip) in local_net
    except ValueError:
        pass
    problems = []          # (level, text)

    # Outage
    if not reached:
        if t.ever_reached:
            problems.append((ALERT, f"Connection to {t.host} is DOWN (no replies)."))
        else:
            problems.append((WARN, f"{t.host} doesn't answer pings/traceroute (may be blocked "
                                   f"by a firewall)."))
    else:
        t.ever_reached = True

    # First hop must be the router when the target is off-subnet
    first = next((h for h in hops if h["ip"]), None)
    if first and not on_subnet and gateway_ip and first["ttl"] == 1 and first["ip"] != gateway_ip:
        try:
            local = local_net is not None and ipaddress.IPv4Address(first["ip"]) in local_net
        except ValueError:
            local = False
        if local:
            problems.append((ALERT, f"Traffic passes through {first['ip']} "
                                    f"({first.get('vendor') or 'unknown vendor'}) before your "
                                    f"router {gateway_ip}."))

    # Same-subnet target: watch its MAC
    if on_subnet:
        mac = neighbors.get(t.ip)
        if mac:
            if t.dest_mac and mac != t.dest_mac:
                problems.append((ALERT, f"{t.host}'s hardware address changed "
                                        f"{t.dest_mac} -> {mac} ({oui.vendor(mac) or '?'})."))
            t.dest_mac = t.dest_mac or mac

    t.runs += 1
    learning = t.runs <= LEARN_RUNS
    if learning:
        t.known |= {h["ip"] for h in hops if h["ip"]}
        if length:
            t.lengths.add(length)
        if stats["avg"] is not None:
            t.rtts.append(stats["avg"])
    else:
        new = [h for h in hops if h["ip"] and h["ip"] not in t.known and h["ip"] != t.ip]
        for h in new:
            label = h["ip"] + (f" [{h['name']}]" if h["name"] else "") + \
                (f" ({h['vendor']})" if h["vendor"] else "")
            problems.append((ALERT, f"NEW device in the path at hop {h['ttl']}: {label}."))
        if length and t.lengths and length not in t.lengths:
            problems.append((WARN, f"Path length changed: {length} hops (normal: "
                                   f"{', '.join(map(str, sorted(t.lengths)))})."))
        if stats["avg"] is not None and t.rtts:
            med = statistics.median(t.rtts)
            if stats["avg"] > max(3 * med, med + 30):
                problems.append((WARN, f"Latency jumped to {stats['avg']:.0f} ms "
                                       f"(normal ~{med:.0f} ms)."))
        if 0 < stats["loss"] < 100 and stats["loss"] >= 25:
            problems.append((WARN, f"Packet loss {stats['loss']:.0f}%."))

    prev_status, prev_summary = t.status, t.summary
    if problems:
        level = ALERT if any(p[0] == ALERT for p in problems) else WARN
        t.status = level
        t.summary = "  |  ".join(p[1] for p in problems)
        t.details = "\n".join(p[1] for p in problems)
    elif learning:
        t.status, t.summary = INFO, f"Learning the normal path ({t.runs}/{LEARN_RUNS})..."
        t.details = ""
    else:
        avg = f"{stats['avg']:.0f} ms" if stats["avg"] is not None else "n/a"
        t.status, t.summary = OK, f"Path normal ({length or '?'} hops, {avg}, " \
                                  f"{stats['loss']:.0f}% loss)."
        t.details = ""
    if t.status in (WARN, ALERT) and (t.status != prev_status or t.summary != prev_summary):
        events.append({"time": time.time(), "level": t.status,
                       "title": f"Path to {t.host}", "message": t.summary,
                       "details": t.details + "\n\n" + format_hops(hops),
                       "action": "Check the listed hop on your network (switch port, ARP "
                                 "table, DHCP lease) to identify the device.", "check": None})
    elif prev_status in (WARN, ALERT) and t.status in (OK, INFO):
        events.append({"time": time.time(), "level": INFO,
                       "title": f"Path to {t.host} - back to normal", "message": t.summary,
                       "details": "", "action": "", "check": None})
    return events


def format_hops(hops):
    lines = []
    for h in hops:
        if h["ip"]:
            rtt = f"{h['rtt']} ms" if h["rtt"] is not None else ""
            extra = " ".join(x for x in (h.get("name"), h.get("mac"), h.get("vendor")) if x)
            lines.append(f"{h['ttl']:>2}  {h['ip']:<16} {rtt:<8} {extra}")
        else:
            lines.append(f"{h['ttl']:>2}  *")
    return "\n".join(lines)
