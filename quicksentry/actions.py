"""Response actions, reports and diagnostics."""

import os
import platform
import time
import traceback

from . import __version__, oui, storage, sysinfo, webchecks, winapi


# --------------------------------------------------------------------------
# Response actions
# --------------------------------------------------------------------------
def disconnect_wifi(alias):
    out = winapi.run(["netsh", "wlan", "disconnect", f"interface={alias}"])
    return "success" in out.lower() or "completed" in out.lower(), out.strip()


def pin_gateway(ifindex, ip, mac):
    """Static ARP entry for the router (until reboot). Needs admin -> UAC prompt."""
    return winapi.run_elevated("netsh", ["interface", "ipv4", "add", "neighbors",
                                         f"interface={ifindex}", f"address={ip}",
                                         f"neighbor={mac.replace(':', '-')}", "store=active"])


def unpin_gateway(ifindex, ip):
    return winapi.run_elevated("netsh", ["interface", "ipv4", "delete", "neighbors",
                                         f"interface={ifindex}", f"address={ip}"])


def is_pinned(ifindex, ip):
    return any(n["ip"] == ip and n["ifindex"] == ifindex and n["state"] == "static"
               for n in winapi.neighbor_table())


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
LEVEL_WORDS = {"ok": "OK", "info": "Info", "warn": "CAUTION", "alert": "ALERT",
               "unknown": "Checking", "off": "Off"}


def build_report(snap, results, overall, alerts, path_targets=None, scan_rows=None):
    L = []
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    L += [f"QuickSentry {__version__} - Network report", f"Generated: {t}",
          f"Computer: {platform.node()}", "=" * 70, ""]
    if snap and snap.get("net_key"):
        a = snap.get("adapter") or {}
        w = snap.get("wifi") or {}
        L += ["CURRENT CONNECTION",
              f"  Network:     {snap.get('net_name')}",
              f"  Adapter:     {snap.get('alias')} ({a.get('description', '')})",
              f"  Security:    {w.get('auth', 'wired')}",
              f"  Access point:{' ' + w['bssid'] if w.get('bssid') else ' n/a'}",
              f"  Your IP:     {', '.join(a.get('ipv4', []))}  mask {a.get('mask')}",
              f"  Router:      {snap.get('gateway_ip')}  {snap.get('gateway_mac')}  "
              f"({oui.vendor(snap.get('gateway_mac')) or 'unknown'})",
              f"  DHCP server: {a.get('dhcp_server')}",
              f"  DNS servers: {', '.join(a.get('dns', []))}", ""]
    L += [f"OVERALL STATUS: {LEVEL_WORDS.get(overall, overall)}", ""]
    L += ["CHECKS"]
    for r in results.values():
        L.append(f"  [{LEVEL_WORDS[r['status']]:>8}] {r['name']}: {r['summary']}")
        if r["details"]:
            L += ["             " + x for x in r["details"].splitlines()]
        if r["action"] and r["status"] in ("warn", "alert"):
            L.append("             What to do: " + r["action"])
    L.append("")
    if snap:
        L.append("DEVICES IN ADDRESS TABLE (IPv4)")
        for ip, mac in sorted(snap.get("neighbors4", {}).items()):
            L.append(f"  {ip:<16} {mac}  {oui.vendor(mac) or ''}")
        n6 = snap.get("neighbors6", [])
        if n6:
            L.append("DEVICES (IPv6)")
            for n in n6:
                L.append(f"  {n['ip']:<40} {n['mac']}  {'ROUTER' if n.get('is_router') else ''}")
        L.append("")
    if path_targets:
        from .pathmon import format_hops
        L.append("PATH MONITOR")
        for tg in path_targets:
            L.append(f"  {tg.host} ({tg.ip}): [{LEVEL_WORDS.get(tg.status, tg.status)}] "
                     f"{tg.summary}")
            L += ["    " + x for x in format_hops(tg.hops).splitlines()]
        L.append("")
    if scan_rows:
        L.append("LAST NETWORK SCAN")
        for r in scan_rows:
            L.append(f"  {r['ip']:<16} {r['mac'] or '-':<18} {r['vendor'] or '':<30} "
                     f"{'; '.join(r['flags'])}")
        L.append("")
    if alerts:
        L.append("RECENT EVENTS")
        for e in alerts[-100:]:
            L.append(f"  {time.strftime('%H:%M:%S', time.localtime(e['time']))} "
                     f"[{LEVEL_WORDS.get(e['level'], e['level'])}] {e['title']}: {e['message']}")
    return "\n".join(L) + "\n"


def save_report(text):
    path = os.path.join(storage.reports_dir(), time.strftime("report-%Y%m%d-%H%M%S.txt"))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# --------------------------------------------------------------------------
# Diagnostics (verifies every collector on this machine)
# --------------------------------------------------------------------------
def diagnostics():
    L = [f"QuickSentry {__version__} diagnostics - {time.strftime('%Y-%m-%d %H:%M:%S')}",
         f"OS: {platform.platform()}  Python: {platform.python_version()}",
         f"Admin: {winapi.is_admin()}  Portable: {storage.is_portable()}",
         f"Data folder: {storage.data_dir()}", ""]

    def section(name, fn):
        L.append(f"--- {name}")
        try:
            L.append(str(fn()))
        except Exception:
            L.append("ERROR:\n" + traceback.format_exc())
        L.append("")

    section("Best route (GetBestRoute)", lambda: winapi.best_route())
    section("Interface alias", lambda: winapi.interface_alias(winapi.best_route()[1]))

    def neigh_api():
        rows = winapi._neighbor_table_api()
        return f"{len(rows)} entries via API; first 5: {rows[:5]}"
    section("Neighbor table (API)", neigh_api)
    section("Neighbor table (arp -a fallback)",
            lambda: f"{len(winapi.parse_arp_a(winapi.run(['arp', '-a'])))} entries")

    def icmp():
        gw = winapi.best_route()[0]
        r1 = winapi._icmp_api(gw, 128, 1000) if gw else "no gateway"
        r2 = winapi._icmp_api("1.1.1.1", 1, 1000)
        return f"ping gateway: {r1}\nTTL=1 to 1.1.1.1: {r2}  (expect status 11013 from gateway)"
    section("ICMP (API)", icmp)
    section("ICMP (ping.exe fallback)", lambda: winapi._icmp_subprocess("1.1.1.1", 1, 1000))

    def ipc():
        ad = sysinfo.parse_ipconfig(winapi.run(["ipconfig", "/all"]))
        return "\n".join(f"{n}: connected={a['connected']} ipv4={a['ipv4']} gw4={a['gateways4']} "
                         f"gw6={a['gateways6']} dhcp={a.get('dhcp_server')} dns4={a['dns4']} "
                         f"dns6={a['dns6']}" for n, a in ad.items()) or "no adapters parsed"
    section("ipconfig /all", ipc)
    section("Wi-Fi interface",
            lambda: sysinfo.parse_wlan_interfaces(winapi.run(["netsh", "wlan", "show", "interfaces"])))

    def scan():
        r = sysinfo.parse_wlan_networks(winapi.run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
        if "networks" in r:
            return f"{len(r['networks'])} networks: " + ", ".join(
                f"{n['ssid'] or '(hidden)'} [{n['auth']}, {len(n['bssids'])} AP]" for n in r["networks"])
        return r
    section("Wi-Fi scan", scan)

    def snap():
        s = sysinfo.snapshot()
        return (f"net={s.get('net_name')} key={s.get('net_key')} gw={s.get('gateway_ip')} "
                f"gwmac={s.get('gateway_mac')} ({oui.vendor(s.get('gateway_mac'))}) "
                f"neighbors4={len(s.get('neighbors4', {}))} neighbors6={len(s.get('neighbors6', []))}")
    section("Full snapshot", snap)
    section("Captive portal", webchecks.captive_portal)
    section("HTTPS", lambda: webchecks.tls_check("www.google.com"))
    section("DNS", webchecks.dns_check)
    return "\n".join(L)
