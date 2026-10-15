"""Detection engine. Pure logic: give it snapshots, it returns check results and events.

Each check result: {key, name, status, summary, details, action}
status: ok | info | warn | alert | unknown | off
"""

import copy
import ipaddress
import time

from . import oui, sysinfo, webchecks, winapi

OK, INFO, WARN, ALERT, UNKNOWN, OFF = "ok", "info", "warn", "alert", "unknown", "off"
RANK = {OFF: 0, OK: 1, UNKNOWN: 1, INFO: 1, WARN: 2, ALERT: 3}

CHECKS = [
    ("gateway", "Router identity"),
    ("spoof", "ARP spoofing signs"),
    ("hardware", "Router hardware"),
    ("route", "Traffic route"),
    ("settings", "Network settings"),
    ("ipv6", "IPv6 safety"),
    ("wifi", "Wi-Fi access point"),
    ("history", "Compared to last visit"),
    ("portal", "Internet / sign-in page"),
    ("https", "HTTPS encryption"),
    ("dns", "Website lookups (DNS)"),
]
NAMES = dict(CHECKS)

ACTION_ALERT = ("Stop sensitive activity (banking, passwords, work logins). Disconnect from "
                "this network or turn on a VPN. If you're on a network you manage, find the "
                "device listed in the details.")
ACTION_WARN = ("Be cautious. Avoid sensitive activity unless you're using a VPN. If you know "
               "why this changed (e.g., the router was replaced), click 'Reset baseline'.")

WIFI_INTERVAL = 30
ROUTE_INTERVAL = 30
PORTAL_RETRY = 30


def mac_label(mac):
    if not mac:
        return "unknown"
    v = oui.vendor(mac)
    return f"{mac} ({v})" if v else mac


def _strip_scope(ip):
    return ip.split("%")[0].lower()


def _is_public(org):
    return any(o in (org or "").lower() for o in webchecks.PUBLIC_CA_ORGS)


def _in_subnet(ip, net):
    try:
        return net is not None and ipaddress.IPv4Address(ip) in net
    except ValueError:
        return False


class Session:
    """Baseline for one connection to one network."""

    def __init__(self, snap, prev_known):
        a = snap.get("adapter") or {}
        self.key = (snap["net_key"], snap.get("ifindex"))
        self.started = time.time()
        self.prev_known = prev_known
        self.gw_ip = snap.get("gateway_ip")
        self.gw_mac = snap.get("gateway_mac")
        self.last_gw_mac = self.gw_mac
        self.dhcp = a.get("dhcp_server")
        self.dns4 = set(a.get("dns4", []))
        self.dns6 = {_strip_scope(d) for d in a.get("dns6", [])}
        self.gw6 = self._v6_routers(snap)
        self.neighbors = dict(snap.get("neighbors4", {}))
        others = self._sharing_gw(snap)
        self.dup_at_start = set(others)
        self.proxy_arp = len(others) >= 3
        self.first_hop = None
        self.tls_issuers = {}
        self.bssid = (snap.get("wifi") or {}).get("bssid")
        self.next_wifi = 0
        self.next_route = 0
        self.next_web = 0
        self.portal = None

    @staticmethod
    def _v6_routers(snap):
        a = snap.get("adapter") or {}
        r = {_strip_scope(g) for g in a.get("gateways6", [])}
        r |= {_strip_scope(n["ip"]) for n in snap.get("neighbors6", []) if n.get("is_router")}
        return r

    def _sharing_gw(self, snap):
        gm = snap.get("gateway_mac")
        if not gm:
            return []
        return [ip for ip, m in snap.get("neighbors4", {}).items()
                if m == gm and ip != snap.get("gateway_ip")]


class Engine:
    def __init__(self, settings, known, collect=None, probe=None, web=None):
        self.settings = settings
        self.known = known                    # dict, persisted by caller
        self.known_dirty = False
        self.collect = collect or sysinfo.snapshot
        self.probe = probe or winapi.icmp_probe
        self.web = web or webchecks
        self.session = None
        self.results = {}
        self.snap = None

    # ------------------------------------------------------------------
    def reset_baseline(self):
        self.session = None
        self.results = {}

    def force_recheck(self):
        if self.session:
            self.session.next_wifi = self.session.next_route = self.session.next_web = 0

    def _set(self, key, status, summary, details="", action=None):
        if action is None:
            action = ACTION_ALERT if status == ALERT else ACTION_WARN if status == WARN else ""
        self.results[key] = {"key": key, "name": NAMES[key], "status": status,
                             "summary": summary, "details": details, "action": action}

    # ------------------------------------------------------------------
    def step(self):
        """Run one monitoring cycle. Returns (snapshot, results, events)."""
        prev = {k: (v["status"], v["summary"]) for k, v in self.results.items()}
        events = []
        snap = self.collect(include_wifi_scan=self.settings.get("check_wifi", True))
        self.snap = snap

        if not snap.get("net_key"):
            if self.session is not None:
                events.append(self._event(INFO, "Disconnected", "No active network connection."))
            self.session = None
            self.results = {}
            for k, _ in CHECKS:
                self._set(k, UNKNOWN, "Not connected to a network.")
            return snap, self.results, events

        if self.session is None or self.session.key != (snap["net_key"], snap.get("ifindex")):
            prev_known = copy.deepcopy(self.known.get(snap["net_key"]))
            self.session = Session(snap, prev_known)
            self.results = {}
            prev = {}
            events.append(self._event(INFO, "Connected",
                                      f"Started monitoring '{snap['net_name']}'. "
                                      f"Router {snap.get('gateway_ip')} = "
                                      f"{mac_label(snap.get('gateway_mac'))}"))
            self._remember(snap, new_visit=True)

        s = self.session
        now = time.time()
        if s.gw_mac is None and snap.get("gateway_mac"):     # late ARP resolution
            s.gw_mac = s.last_gw_mac = snap["gateway_mac"]

        events += self._check_gateway(snap)
        self._check_spoof(snap)
        self._check_hardware(snap)
        self._check_settings(snap)
        if self.settings.get("check_ipv6", True):
            self._check_ipv6(snap)
        else:
            self._set("ipv6", OFF, "Turned off in Settings.")
        if self.settings.get("check_wifi", True):
            if now >= s.next_wifi or "wifi" not in self.results:
                events += self._check_wifi(snap)
                s.next_wifi = now + WIFI_INTERVAL
        else:
            self._set("wifi", OFF, "Turned off in Settings.")
        if self.settings.get("check_first_hop", True):
            if now >= s.next_route:
                self._check_route(snap)
                s.next_route = now + ROUTE_INTERVAL
        else:
            self._set("route", OFF, "Turned off in Settings.")
        self._check_history(snap)
        if self.settings.get("check_web", True):
            if now >= s.next_web:
                self._check_web(snap)
        else:
            for k in ("portal", "https", "dns"):
                self._set(k, OFF, "Turned off in Settings.")
        for k, _ in CHECKS:
            if k not in self.results:
                self._set(k, UNKNOWN, "Waiting for first check...")

        self._remember(snap)

        # Transition events
        for k, r in self.results.items():
            ps, psum = prev.get(k, (None, None))
            if r["status"] in (WARN, ALERT) and (
                    RANK[r["status"]] > RANK.get(ps, 0) or
                    (r["status"] == ALERT and r["summary"] != psum)):
                events.append(self._event(r["status"], r["name"], r["summary"],
                                          r["details"], r["action"], k))
            elif ps in (WARN, ALERT) and RANK[r["status"]] < RANK[WARN]:
                events.append(self._event(INFO, r["name"] + " - back to normal", r["summary"],
                                          check=k))
        return snap, self.results, events

    def overall(self):
        if not self.results or not self.session:
            return UNKNOWN
        worst = max((RANK[r["status"]] for r in self.results.values()), default=1)
        return ALERT if worst == 3 else WARN if worst == 2 else OK

    @staticmethod
    def _event(level, title, message, details="", action="", check=None):
        return {"time": time.time(), "level": level, "title": title, "message": message,
                "details": details, "action": action, "check": check}

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------
    def _check_gateway(self, snap):
        s, events = self.session, []
        cur = snap.get("gateway_mac")
        if not cur:
            self._set("gateway", UNKNOWN, "Couldn't read the router's hardware address yet.")
            return events
        if s.gw_ip and snap.get("gateway_ip") != s.gw_ip:
            self._set("gateway", INFO, "Router address changed (see Network settings).")
            return events
        if cur != s.last_gw_mac:
            if cur == s.gw_mac:
                events.append(self._event(INFO, "Router address changed back",
                                          f"Router {s.gw_ip} is back to its original "
                                          f"hardware address {mac_label(cur)}."))
            # other neighbor MAC changes are logged quietly
            s.last_gw_mac = cur
        for ip, mac in snap.get("neighbors4", {}).items():
            old = s.neighbors.get(ip)
            if ip != s.gw_ip and old and old != mac:
                events.append(self._event(INFO, "Device address changed",
                                          f"{ip} changed from {old} to {mac}. Usually harmless "
                                          f"(a device reconnected)."))
            s.neighbors[ip] = mac
        if cur != s.gw_mac:
            self._set("gateway", ALERT,
                      "The router's hardware address CHANGED since you connected.",
                      f"Router IP: {s.gw_ip}\nOriginal MAC: {mac_label(s.gw_mac)}\n"
                      f"Current MAC:  {mac_label(cur)}\n\nThis is the classic sign of ARP "
                      f"spoofing: another device is claiming to be your router so your traffic "
                      f"flows through it. It can also happen if the router was replaced or the "
                      f"network failed over to a backup router.")
        else:
            pinned = s.gw_ip in snap.get("neighbors4_static", set())
            self._set("gateway", OK,
                      "Router hardware address unchanged since you connected." +
                      (" (Pinned)" if pinned else ""),
                      f"Router IP: {s.gw_ip}\nRouter MAC: {mac_label(cur)}")
        return events

    def _check_spoof(self, snap):
        s = self.session
        gm, gip = snap.get("gateway_mac"), snap.get("gateway_ip")
        n4 = snap.get("neighbors4", {})
        if not gm:
            self._set("spoof", UNKNOWN, "Waiting for the router's hardware address.")
            return
        sharing = sorted(ip for ip, m in n4.items() if m == gm and ip != gip)
        new = sorted(set(sharing) - s.dup_at_start)
        by_mac = {}
        for ip, m in n4.items():
            by_mac.setdefault(m, []).append(ip)
        other_dups = {m: ips for m, ips in by_mac.items() if len(ips) > 1 and m != gm}
        lines = [f"{ip} -> {gm}" for ip in sharing]
        if s.proxy_arp:
            self._set("spoof", INFO,
                      "This network answers for many addresses with the router's address "
                      "(proxy ARP). The duplicate-address check is less reliable here.",
                      "Addresses sharing the router MAC:\n" + "\n".join(lines))
        elif new:
            self._set("spoof", ALERT,
                      f"Another device ({', '.join(new)}) is using the router's hardware "
                      f"address.",
                      "Two different IP addresses answer with the same hardware address as "
                      "your router. That usually means one device is pretending to be the "
                      "router (ARP spoofing).\n\n" + "\n".join(lines) +
                      f"\nRouter: {gip} = {mac_label(gm)}")
        elif sharing:
            self._set("spoof", WARN,
                      f"{', '.join(sharing)} shares the router's hardware address (already "
                      f"present when you connected).",
                      "Can be normal if the router has several addresses, but it is also what "
                      "ARP spoofing looks like if it started before monitoring.\n\n" +
                      "\n".join(lines))
        elif other_dups:
            d = "\n".join(f"{m}: {', '.join(sorted(ips))}" for m, ips in other_dups.items())
            self._set("spoof", INFO, "Some devices share a hardware address (not the router).",
                      "Usually harmless (one device with several addresses).\n\n" + d)
        else:
            self._set("spoof", OK, "No signs of ARP spoofing.",
                      f"{len(n4)} devices in the address table, no duplicates of the router.")

    def _check_hardware(self, snap):
        gm = snap.get("gateway_mac")
        if not gm:
            self._set("hardware", UNKNOWN, "Waiting for the router's hardware address.")
            return
        cat, v = oui.category(gm), oui.vendor(gm) or "unknown manufacturer"
        det = f"Router MAC: {gm}\nManufacturer: {v}"
        if cat == "attack_tool":
            self._set("hardware", ALERT, f"Router hardware matches a known hacking device ({v}).",
                      det)
        elif cat == "randomized":
            self._set("hardware", WARN,
                      "Router uses a randomized (private) hardware address.",
                      det + "\n\nReal routers almost never do this. Laptops and phones do, "
                      "which is what an attacker would use. Normal if you're connected to a "
                      "phone hotspot.")
        elif cat in ("virtual", "sbc"):
            self._set("hardware", WARN, f"Router looks like a {('virtual machine' if cat == 'virtual' else 'Raspberry Pi')} ({v}).",
                      det + "\n\nUnusual for public Wi-Fi. Common in labs and home setups.")
        elif cat == "endpoint":
            self._set("hardware", WARN,
                      f"Router hardware is made by {v}, which mostly makes laptops/phones.",
                      det + "\n\nNormal for phone hotspots and some home routers. On public "
                      "Wi-Fi it can mean a laptop is acting as the router.")
        elif cat == "unknown":
            self._set("hardware", INFO, "Router manufacturer not in the database.", det)
        else:
            self._set("hardware", OK, f"Router made by {v}.", det)

    def _check_settings(self, snap):
        s = self.session
        a = snap.get("adapter") or {}
        changes = []
        if s.gw_ip and snap.get("gateway_ip") and snap["gateway_ip"] != s.gw_ip:
            changes.append(f"Router address: {s.gw_ip} -> {snap['gateway_ip']}")
        dhcp = a.get("dhcp_server")
        if s.dhcp and dhcp and dhcp != s.dhcp:
            changes.append(f"DHCP server: {s.dhcp} -> {dhcp}")
        dns4 = set(a.get("dns4", []))
        if s.dns4 and dns4 and dns4 != s.dns4:
            changes.append(f"DNS servers: {', '.join(sorted(s.dns4))} -> "
                           f"{', '.join(sorted(dns4))}")
        det = (f"Router: {snap.get('gateway_ip')}\nDHCP server: {dhcp or 'n/a'}\n"
               f"DNS servers: {', '.join(a.get('dns4', [])) or 'n/a'}\n"
               f"Your IP: {', '.join(a.get('ipv4', [])) or 'n/a'}")
        if changes:
            self._set("settings", ALERT,
                      "Network settings changed without reconnecting.",
                      "\n".join(changes) + "\n\nA rogue DHCP server can hand out a fake "
                      "router or DNS server to redirect your traffic.\n\n" + det)
        else:
            note = ""
            if dhcp and snap.get("gateway_ip") and dhcp != snap["gateway_ip"]:
                note = "\n\nNote: the DHCP server is a different device than the router " \
                       "(common on larger networks)."
            self._set("settings", OK, "Router, DHCP and DNS settings are stable.", det + note)

    def _check_ipv6(self, snap):
        s = self.session
        a = snap.get("adapter") or {}
        routers = Session._v6_routers(snap)
        dns6 = {_strip_scope(d) for d in a.get("dns6", [])}
        n6 = {_strip_scope(n["ip"]): n["mac"] for n in snap.get("neighbors6", [])}
        router_macs = {n6[r] for r in routers if r in n6}
        gm = snap.get("gateway_mac")
        det = (f"IPv6 routers: {', '.join(f'{r} ({mac_label(n6.get(r))})' for r in sorted(routers)) or 'none'}\n"
               f"IPv6 DNS servers: {', '.join(sorted(dns6)) or 'none'}")
        new_r, new_d = routers - s.gw6, dns6 - s.dns6
        if new_r or new_d:
            what = []
            if new_r:
                what.append("router " + ", ".join(f"{r} ({mac_label(n6.get(r))})"
                                                  for r in sorted(new_r)))
            if new_d:
                what.append("DNS server " + ", ".join(sorted(new_d)))
            self._set("ipv6", ALERT, "A new IPv6 " + " and ".join(what) + " appeared.",
                      "Attack tools like mitm6 announce themselves as an IPv6 router/DNS "
                      "server. Windows prefers IPv6, so it starts sending lookups to the "
                      "attacker.\n\n" + det)
        elif dns6 and not routers:
            self._set("ipv6", WARN,
                      "You received an IPv6 DNS server but there is no IPv6 router.",
                      "This is the exact pattern the mitm6 attack tool creates. It can be "
                      "normal on some home routers.\n\n" + det)
        elif gm and router_macs and gm not in router_macs:
            self._set("ipv6", WARN, "The IPv6 router is a different device than your router.",
                      f"IPv4 router MAC: {mac_label(gm)}\n" + det +
                      "\n\nUsually one box does both. A separate IPv6 router can be a rogue "
                      "device sending fake router advertisements.")
        elif len(router_macs) > 1:
            self._set("ipv6", WARN, "More than one IPv6 router is active.", det)
        elif not routers and not dns6:
            self._set("ipv6", OK, "No IPv6 routers or DNS servers on this network.", det)
        else:
            self._set("ipv6", OK, "IPv6 router and DNS look consistent.", det)

    def _check_wifi(self, snap):
        events = []
        s = self.session
        w = snap.get("wifi")
        if snap.get("wifi_error") == "location":
            self._set("wifi", UNKNOWN, "Windows is blocking Wi-Fi details.",
                      sysinfo.LOCATION_HINT, sysinfo.LOCATION_HINT)
            return events
        if not w:
            self._set("wifi", OFF, "Wired connection - Wi-Fi checks not needed.")
            return events
        ssid, bssid, auth = w.get("ssid", ""), w.get("bssid"), w.get("auth", "")
        if bssid and s.bssid and bssid != s.bssid:
            events.append(self._event(INFO, "Switched access point",
                                      f"Roamed from {mac_label(s.bssid)} to {mac_label(bssid)} "
                                      f"on '{ssid}'. Normal in large buildings."))
            s.bssid = bssid
        scan = (snap.get("wifi_scan") or {}).get("networks") or []
        same = [n for n in scan if n["ssid"] == ssid]
        auths = sorted({n["auth"] for n in same if n["auth"]})
        aps = [b["bssid"] for n in same for b in n["bssids"] if b.get("bssid")]
        vendors = sorted({oui.vendor(b) for b in aps
                          if oui.category(b) not in ("randomized", "unknown")})
        det = (f"Network: {ssid}\nSecurity: {auth} / {w.get('cipher', '')}\n"
               f"Connected access point: {mac_label(bssid)}\n"
               f"Signal: {w.get('signal', '?')}  Channel: {w.get('channel', '?')}\n"
               f"Access points nearby with this name: {len(aps)}\n"
               f"Security types seen for this name: {', '.join(auths) or 'n/a'}\n"
               f"Access point manufacturers: {', '.join(vendors) or 'n/a'}")
        open_now = sysinfo.is_open_auth(auth)
        cat = oui.category(bssid) if bssid else "unknown"
        if len(auths) > 1 and any(sysinfo.is_open_auth(x) for x in auths):
            self._set("wifi", ALERT,
                      f"Two versions of '{ssid}' are nearby: one secured, one OPEN.",
                      "Fake 'evil twin' hotspots copy a real network's name but leave off the "
                      "password so devices join them.\n\n" + det)
        elif cat == "attack_tool":
            self._set("wifi", ALERT, "The access point matches a known hacking device.", det)
        elif cat == "randomized":
            self._set("wifi", WARN, "The access point uses a randomized hardware address.",
                      "Normal for phone hotspots. Unusual for a business's Wi-Fi.\n\n" + det)
        elif open_now:
            self._set("wifi", INFO,
                      "Open network (no password). Anyone nearby can see unencrypted traffic.",
                      det, "Use a VPN on open networks. Stick to HTTPS websites.")
        elif len(auths) > 1:
            self._set("wifi", INFO, f"'{ssid}' is broadcast with more than one security type.",
                      "Often normal (WPA2/WPA3 transition mode).\n\n" + det)
        elif len(vendors) > 1:
            self._set("wifi", INFO, "Access points from different manufacturers use this name.",
                      "Can be normal in big venues, but fake hotspots also cause this.\n\n" + det)
        else:
            self._set("wifi", OK, f"Connected to '{ssid}' ({auth}). No look-alike networks seen.",
                      det)
        return events

    def _check_route(self, snap):
        s = self.session
        gip = snap.get("gateway_ip")
        net = sysinfo.local_subnet(snap)

        def probe():
            st, frm, rtt = self.probe("1.1.1.1", ttl=1, timeout_ms=1000)
            return st, frm

        st, frm = probe()
        if frm and frm != gip and _in_subnet(frm, net):
            st, frm = probe()          # confirm before raising an alarm
        if not frm:
            self._set("route", INFO, "The router doesn't answer route tests (can't verify).",
                      "Some routers silently drop these test packets.")
            return
        if st == winapi.IP_SUCCESS:
            self._set("route", INFO, "Unusual: the internet answered at the first hop.",
                      f"Reply from {frm}. Some captive portals do this.")
            return
        if s.first_hop is None:
            s.first_hop = frm
        mac = snap.get("neighbors4", {}).get(frm)
        det = (f"First device your traffic reaches: {frm} ({mac_label(mac)})\n"
               f"Your router: {gip} ({mac_label(snap.get('gateway_mac'))})\n"
               f"First hop when monitoring started: {s.first_hop}")
        if frm != gip and _in_subnet(frm, net):
            self._set("route", ALERT,
                      f"Your traffic passes through {frm} before reaching the router.",
                      "A device on your local network is forwarding your traffic. This is "
                      "how most man-in-the-middle tools work.\n\n" + det)
        elif frm != s.first_hop:
            self._set("route", ALERT, f"The first hop changed from {s.first_hop} to {frm}.", det)
        elif frm != gip:
            self._set("route", INFO,
                      f"The router answered from a different address ({frm}).",
                      "Common on some routers and corporate networks.\n\n" + det)
        else:
            self._set("route", OK, "Traffic goes straight to your router.", det)

    def _check_history(self, snap):
        s = self.session
        p = s.prev_known
        w = snap.get("wifi") or {}
        if not p:
            self._set("history", INFO,
                      "First time on this network. ARP Watch will remember it for next time.")
            return
        visits = p.get("visits", 1)
        problems, warn = [], False
        gm = snap.get("gateway_mac")
        if gm and p.get("gateway_macs") and gm not in p["gateway_macs"]:
            warn = True
            problems.append(f"The router is a different device than on previous visits "
                            f"({mac_label(gm)}; before: {', '.join(p['gateway_macs'][-3:])}). "
                            f"Normal if this is a different location of the same chain.")
        if w.get("auth") and sysinfo.is_open_auth(w["auth"]) and any(
                not sysinfo.is_open_auth(x) for x in p.get("auths", [])):
            self._set("history", ALERT,
                      "This network used to require a password and is now OPEN.",
                      "Security downgrade: previous visits used "
                      f"{', '.join(p.get('auths', []))}, now {w['auth']}. Fake hotspots "
                      "often copy a known network's name without the password.")
            return
        a = snap.get("adapter") or {}
        if a.get("dns6") and not p.get("ipv6_dns", False):
            warn = True
            problems.append("IPv6 DNS appeared; previous visits had none.")
        if warn:
            self._set("history", WARN, "Differs from previous visits.", "\n".join(problems))
        else:
            self._set("history", OK, f"Matches previous visits (seen {visits} times).",
                      f"First seen: {time.strftime('%Y-%m-%d', time.localtime(p.get('first_seen', 0)))}")

    def _check_web(self, snap):
        s = self.session
        now = time.time()
        portal = self.web.captive_portal()
        s.portal = portal
        if portal == "portal":
            self._set("portal", INFO, "Sign-in page detected (hotel / coffee shop login).",
                      "HTTPS and DNS checks are paused until you're signed in, because login "
                      "pages intentionally redirect traffic.")
            for k in ("https", "dns"):
                self._set(k, UNKNOWN, "Waiting for you to sign in to the network.")
            s.next_web = now + PORTAL_RETRY
            return
        if portal == "offline":
            self._set("portal", INFO, "No internet access right now.")
            for k in ("https", "dns"):
                self._set(k, UNKNOWN, "No internet access.")
            s.next_web = now + PORTAL_RETRY
            return
        self._set("portal", OK, "Internet access OK (no sign-in page).")
        s.next_web = now + self.settings.get("web_interval", 300)

        # HTTPS
        results = [self.web.tls_check(h) for h in webchecks.TLS_HOSTS]
        lines = []
        for r in results:
            if r["ok"]:
                lines.append(f"{r['host']}: issued by {r['issuer']}")
            else:
                lines.append(f"{r['host']}: {r['error']}")
        det = "\n".join(lines)
        bad = [r for r in results if r["ok"] is False]
        tested = [r for r in results if r["ok"]]
        inspected = sorted({r["issuer"] for r in tested if not r["public_ca"]})
        changed = []
        for r in tested:
            old = s.tls_issuers.get(r["host"])
            if old and old != r["issuer"] and not (r["public_ca"] and _is_public(old)):
                changed.append(f"{r['host']}: {old} -> {r['issuer']}")
            s.tls_issuers.setdefault(r["host"], r["issuer"])
        prev_iss = set(((s.prev_known or {}).get("tls_issuers") or {}).values())
        if bad:
            self._set("https", ALERT,
                      f"Secure certificate check FAILED for {', '.join(r['host'] for r in bad)}.",
                      "Something is intercepting encrypted connections with a certificate your "
                      "computer doesn't trust. Don't log in to anything.\n\n" + det)
        elif changed:
            self._set("https", ALERT, "Who signs secure connections changed mid-session.",
                      "\n".join(changed) + "\n\n" + det)
        elif inspected:
            known_before = set(inspected) <= prev_iss
            self._set("https", INFO if known_before else WARN,
                      f"Secure connections are being inspected by '{', '.join(inspected)}'.",
                      "Normal on many school/work networks with web filters (the computer "
                      "trusts the filter's certificate). On public Wi-Fi it would mean "
                      "someone can read your HTTPS traffic.\n\n" + det)
        elif not tested:
            self._set("https", UNKNOWN, "Couldn't reach the test websites.", det)
        else:
            self._set("https", OK, "Secure connections look genuine.", det)
        if tested:
            rec = self.known.get(snap["net_key"])
            if rec is not None:
                rec.setdefault("tls_issuers", {}).update(
                    {r["host"]: r["issuer"] for r in tested})
                self.known_dirty = True

        # DNS
        d = self.web.dns_check()
        if d["wrong"]:
            w = "; ".join(f"{h} -> {', '.join(a)}" for h, a in d["wrong"])
            self._set("dns", ALERT, "Website lookups are returning WRONG addresses.",
                      f"{w}\n\nThese names always have fixed addresses. A wrong answer means "
                      f"something is rewriting DNS (an attacker, or a strict web filter).")
        elif len(d["failed"]) == len(webchecks.DNS_FIXED):
            self._set("dns", UNKNOWN, "Website lookups failed.", "DNS may be blocked or down.")
        elif d["nx_hijack"]:
            self._set("dns", INFO, "This network redirects mistyped web addresses.",
                      "Common on hotel and ISP networks (ad/search pages). Not an attack "
                      "by itself.")
        else:
            self._set("dns", OK, "Website lookups return correct answers.")

    # ------------------------------------------------------------------
    def _remember(self, snap, new_visit=False):
        key = snap["net_key"]
        rec = self.known.setdefault(key, {
            "name": snap.get("net_name"), "first_seen": time.time(), "visits": 0,
            "gateway_macs": [], "gateway_ips": [], "auths": [], "bssids": [],
            "ipv6_dns": False, "tls_issuers": {}})
        before = repr(rec)
        if new_visit:
            rec["visits"] = rec.get("visits", 0) + 1
            rec["last_seen"] = time.time()
        s = self.session
        bad = any(self.results.get(k, {}).get("status") == ALERT
                  for k in ("gateway", "spoof", "hardware", "route", "wifi", "history"))
        if not bad:
            gm = s.gw_mac if s else None
            if gm and gm not in rec["gateway_macs"]:
                rec["gateway_macs"] = (rec["gateway_macs"] + [gm])[-10:]
            gip = snap.get("gateway_ip")
            if gip and gip not in rec["gateway_ips"]:
                rec["gateway_ips"] = (rec["gateway_ips"] + [gip])[-10:]
            w = snap.get("wifi") or {}
            if w.get("auth") and w["auth"] not in rec["auths"]:
                rec["auths"].append(w["auth"])
            if w.get("bssid") and w["bssid"] not in rec["bssids"]:
                rec["bssids"] = (rec["bssids"] + [w["bssid"]])[-50:]
            if (snap.get("adapter") or {}).get("dns6"):
                rec["ipv6_dns"] = True
        if repr(rec) != before:
            self.known_dirty = True
