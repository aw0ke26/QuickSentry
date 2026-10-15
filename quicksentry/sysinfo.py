"""Collect a snapshot of the current network state on Windows.

Text parsers (ipconfig / netsh) expect English Windows output. If parsing fails,
the related checks report 'unavailable' instead of guessing.
"""

import ipaddress
import re
import time

from . import oui, winapi

LOCATION_HINT = ("Windows is blocking Wi-Fi details. Turn on Location services "
                 "(Settings > Privacy & security > Location) and allow desktop apps.")

# Windows puts these placeholder IPv6 DNS servers on adapters with no real IPv6 DNS
_PLACEHOLDER_V6_DNS = {"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"}


# --------------------------------------------------------------------------
# ipconfig /all
# --------------------------------------------------------------------------
_KEYS = {
    "description": "description",
    "physical address": "mac",
    "dhcp enabled": "dhcp_enabled",
    "ipv4 address": "ipv4",
    "autoconfiguration ipv4 address": "ipv4",
    "subnet mask": "mask",
    "default gateway": "gateways",
    "dhcp server": "dhcp_server",
    "dns servers": "dns",
    "connection-specific dns suffix": "dns_suffix",
    "media state": "media_state",
    "ipv6 address": "ipv6",
    "temporary ipv6 address": "ipv6",
    "link-local ipv6 address": "ipv6_ll",
}
_LIST_KEYS = {"gateways", "dns", "ipv4", "ipv6", "ipv6_ll"}


def _clean_addr(v):
    return re.sub(r"\((Preferred|Deprecated|Tentative|Duplicate)\)", "", v).strip()


def parse_ipconfig(text):
    """Return {adapter_name: {...}}. Adapter name = alias, e.g. 'Wi-Fi'."""
    adapters, cur, last_key = {}, None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not raw.startswith(" ") and line.endswith(":"):
            # "Wireless LAN adapter Wi-Fi:" / "Ethernet adapter Ethernet 2:"
            m = re.match(r"^(.*?adapter)\s+(.+):$", line)
            if m:
                cur = {"name": m.group(2), "kind": m.group(1), "gateways": [], "dns": [],
                       "ipv4": [], "ipv6": [], "ipv6_ll": [], "mask": None}
                adapters[cur["name"]] = cur
            else:
                cur = None
            last_key = None
            continue
        if cur is None:
            continue
        if " : " in line:
            k, v = line.split(" : ", 1)
            k = re.sub(r"[ .]+$", "", k.strip()).lower()
            last_key = _KEYS.get(k)
            if last_key is None:
                continue
            v = _clean_addr(v)
            if last_key in _LIST_KEYS:
                if v:
                    cur[last_key].append(v)
            else:
                cur[last_key] = v
        elif last_key in _LIST_KEYS:
            v = _clean_addr(line)
            if v:
                cur[last_key].append(v)
    for a in adapters.values():
        a["mac"] = oui.normalize(a.get("mac", ""))
        a["ipv4"] = [ip for ip in a["ipv4"] if _is_v4(ip)]
        a["gateways4"] = [g for g in a["gateways"] if _is_v4(g)]
        a["gateways6"] = [g for g in a["gateways"] if not _is_v4(g)]
        a["dns4"] = [d for d in a["dns"] if _is_v4(d)]
        a["dns6"] = [d for d in a["dns"] if not _is_v4(d)
                     and d.split("%")[0].lower() not in _PLACEHOLDER_V6_DNS]
        a["connected"] = "disconnected" not in a.get("media_state", "").lower()
    return adapters


def _is_v4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# netsh wlan
# --------------------------------------------------------------------------
def _kv_lines(text):
    for line in text.splitlines():
        if " : " in line:
            k, v = line.split(" : ", 1)   # split on ' : ' so MACs/IPv6 stay intact
            yield line, k.strip(), v.strip()


def parse_wlan_interfaces(text):
    """List of Wi-Fi interface dicts from `netsh wlan show interfaces`."""
    if "location" in text.lower() and "permission" in text.lower():
        return {"error": "location"}
    ifaces, cur = [], None
    for _, k, v in _kv_lines(text):
        kl = k.lower()
        if kl == "name":
            cur = {"name": v}
            ifaces.append(cur)
        elif cur is None:
            continue
        elif kl == "state":
            cur["state"] = v.lower()
        elif kl == "ssid":
            cur["ssid"] = v
        elif kl in ("bssid", "ap bssid"):
            cur["bssid"] = oui.normalize(v)
        elif kl == "authentication":
            cur["auth"] = v
        elif kl == "cipher":
            cur["cipher"] = v
        elif kl == "signal":
            cur["signal"] = v
        elif kl == "channel":
            cur["channel"] = v
        elif kl == "band":
            cur["band"] = v
    return {"interfaces": ifaces}


def parse_wlan_networks(text):
    """List of {ssid, auth, encryption, bssids:[{bssid, signal, channel}]}"""
    if "location" in text.lower() and "permission" in text.lower():
        return {"error": "location"}
    nets, cur, cur_b = [], None, None
    for line, k, v in _kv_lines(text):
        kl = k.lower()
        if re.match(r"^ssid \d+$", kl):
            cur = {"ssid": v, "auth": "", "encryption": "", "bssids": []}
            nets.append(cur)
            cur_b = None
        elif cur is None:
            continue
        elif kl == "authentication":
            cur["auth"] = v
        elif kl == "encryption":
            cur["encryption"] = v
        elif re.match(r"^bssid \d+$", kl):
            cur_b = {"bssid": oui.normalize(v)}
            cur["bssids"].append(cur_b)
        elif cur_b is not None and kl in ("signal", "channel", "band", "radio type"):
            cur_b[kl.replace(" ", "_")] = v
    return {"networks": nets}


def is_open_auth(auth):
    return (auth or "").strip().lower().startswith("open")


# --------------------------------------------------------------------------
# Snapshot
# --------------------------------------------------------------------------
_wlan_cache = {"t": 0, "nets": None}


def wifi_scan(max_age=30):
    """Cached nearby-network scan (cheap; Windows caches scan results anyway)."""
    if time.time() - _wlan_cache["t"] > max_age or _wlan_cache["nets"] is None:
        _wlan_cache["nets"] = parse_wlan_networks(
            winapi.run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
        _wlan_cache["t"] = time.time()
    return _wlan_cache["nets"]


def snapshot(include_wifi_scan=True):
    """Everything the detectors need, in one dict."""
    snap = {"time": time.time(), "error": None}
    gw, ifindex = winapi.best_route("1.1.1.1")
    snap["gateway_ip"] = gw
    snap["ifindex"] = ifindex
    alias = winapi.interface_alias(ifindex)

    adapters = parse_ipconfig(winapi.run(["ipconfig", "/all"]))
    adapter = None
    if alias and alias in adapters:
        adapter = adapters[alias]
    elif gw:
        adapter = next((a for a in adapters.values() if gw in a["gateways4"]), None)
    snap["vpn"] = None
    if adapter is None or not adapter["gateways4"]:
        # Internet traffic goes through an adapter with no gateway (typically a VPN).
        # Watch the physical network underneath instead; prefer Wi-Fi.
        phys = [a for a in adapters.values() if a["connected"] and a["gateways4"]]
        phys.sort(key=lambda a: 0 if "wireless" in a["kind"].lower() else 1)
        if phys:
            if alias:
                snap["vpn"] = alias
            adapter = phys[0]
            gw = adapter["gateways4"][0]
            ifindex = winapi.best_route(gw)[1] or None
            snap["ifindex"] = ifindex
            alias = adapter["name"]
    snap["adapter"] = adapter
    snap["alias"] = alias or (adapter["name"] if adapter else None)
    if adapter and adapter["gateways4"] and (not gw or snap["vpn"]):
        gw = gw or adapter["gateways4"][0]
    snap["gateway_ip"] = gw

    # Neighbors (only on the active interface when we know it)
    neigh = winapi.neighbor_table()
    if ifindex:
        neigh = [n for n in neigh if n["ifindex"] == ifindex]
    snap["neighbors4"] = {n["ip"]: n["mac"] for n in neigh if n["family"] == 4}
    snap["neighbors4_static"] = {n["ip"] for n in neigh if n["family"] == 4
                                 and n["state"] == "static"}
    snap["neighbors6"] = [n for n in neigh if n["family"] == 6]
    if gw and gw not in snap["neighbors4"]:
        winapi.icmp_probe(gw, timeout_ms=500)      # populate the ARP entry
        neigh = winapi.neighbor_table()
        for n in neigh:
            if n["family"] == 4 and n["ip"] == gw:
                snap["neighbors4"][gw] = n["mac"]
    snap["gateway_mac"] = snap["neighbors4"].get(gw) if gw else None

    # Wi-Fi
    snap["wifi"] = None
    snap["wifi_error"] = None
    wl = parse_wlan_interfaces(winapi.run(["netsh", "wlan", "show", "interfaces"]))
    if wl.get("error") == "location":
        snap["wifi_error"] = "location"
    else:
        for w in wl.get("interfaces", []):
            if w.get("state") == "connected" and (not snap["alias"] or w["name"] == snap["alias"]):
                snap["wifi"] = w
                break
    snap["wifi_scan"] = wifi_scan() if (include_wifi_scan and snap["wifi"]) else None

    # Network identity key (used to remember networks between visits)
    if snap["wifi"] and snap["wifi"].get("ssid"):
        snap["net_key"] = "wifi:" + snap["wifi"]["ssid"]
        snap["net_name"] = snap["wifi"]["ssid"]
    elif adapter and gw:
        suffix = adapter.get("dns_suffix") or ""
        snap["net_key"] = f"wired:{adapter['name']}:{gw}:{suffix}"
        snap["net_name"] = f"{adapter['name']} ({suffix or gw})"
    else:
        snap["net_key"] = None
        snap["net_name"] = None
    return snap


def local_subnet(snap):
    """ipaddress.IPv4Network for the active adapter, or None."""
    a = snap.get("adapter") or {}
    if a.get("ipv4") and a.get("mask"):
        try:
            return ipaddress.IPv4Interface(f"{a['ipv4'][0]}/{a['mask']}").network
        except ValueError:
            return None
    return None
