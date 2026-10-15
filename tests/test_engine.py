import copy, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from arpwatch import engine as E, winapi

GW = "192.168.1.1"; GWMAC = "00:1a:1e:aa:bb:cc"; ATK = "a4:5e:60:11:22:33"  # Apple
def base_snap(**kw):
    s = {"time": 0, "net_key": "wifi:CoffeeShop", "net_name": "CoffeeShop", "ifindex": 12,
         "gateway_ip": GW, "gateway_mac": GWMAC,
         "adapter": {"name": "Wi-Fi", "ipv4": ["192.168.1.50"], "mask": "255.255.255.0",
                     "gateways4": [GW], "gateways6": [], "dhcp_server": GW,
                     "dns4": [GW], "dns6": []},
         "neighbors4": {GW: GWMAC, "192.168.1.20": "00:11:22:33:44:55"},
         "neighbors4_static": set(), "neighbors6": [],
         "wifi": {"name": "Wi-Fi", "ssid": "CoffeeShop", "bssid": "00:1a:1e:11:22:33",
                  "auth": "WPA2-Personal", "cipher": "CCMP", "state": "connected"},
         "wifi_error": None,
         "wifi_scan": {"networks": [{"ssid": "CoffeeShop", "auth": "WPA2-Personal",
                                     "bssids": [{"bssid": "00:1a:1e:11:22:33"}]}]}}
    s.update(kw); return s

class FakeWeb:
    portal = "online"; tls_issuer = "Google Trust Services"; tls_ok = True; dns_wrong = []
    def captive_portal(self): return self.portal
    def tls_check(self, h):
        if not self.tls_ok:
            return {"host": h, "ok": False, "issuer": None, "public_ca": None, "error": "certificate not trusted"}
        pub = any(o in self.tls_issuer.lower() for o in E.webchecks.PUBLIC_CA_ORGS)
        return {"host": h, "ok": True, "issuer": self.tls_issuer, "public_ca": pub, "error": None}
    def dns_check(self): return {"wrong": self.dns_wrong, "failed": [], "nx_hijack": False}

class Rig:
    def __init__(self, known=None):
        self.snap = base_snap(); self.hop = GW; self.web = FakeWeb()
        self.e = E.Engine({"web_interval": 300}, known if known is not None else {},
                          collect=lambda include_wifi_scan=True: copy.deepcopy(self.snap),
                          probe=lambda ip, ttl=1, timeout_ms=1000: (winapi.IP_TTL_EXPIRED_TRANSIT, self.hop, 1),
                          web=self.web)
    def step(self, force=True):
        if force: self.e.force_recheck()
        snap, res, ev = self.e.step()
        return {k: v["status"] for k, v in res.items()}, ev, res

def show(name, st, ev, keys=None):
    bad = {k: v for k, v in st.items() if v in ("warn", "alert")}
    print(f"{name:42s} overall={'-'} bad={bad} events={[ (e['level'], e['title']) for e in ev]}")

r = Rig(); st, ev, _ = r.step(); show("1 clean network", st, ev); assert r.e.overall() == "ok", st
r.snap["gateway_mac"] = ATK; r.snap["neighbors4"][GW] = ATK
st, ev, res = r.step(); show("2 gateway MAC changes", st, ev); assert st["gateway"] == "alert"
r.snap["gateway_mac"] = GWMAC; r.snap["neighbors4"][GW] = GWMAC
st, ev, _ = r.step(); show("3 reverted", st, ev); assert st["gateway"] == "ok"

r = Rig(); r.step(); r.snap["neighbors4"]["192.168.1.66"] = GWMAC
st, ev, _ = r.step(); show("4 new IP shares gateway MAC", st, ev); assert st["spoof"] == "alert"

r = Rig(); r.step(); r.hop = "192.168.1.66"; r.snap["neighbors4"]["192.168.1.66"] = ATK
st, ev, res = r.step(); show("5 first hop is not gateway", st, ev); assert st["route"] == "alert"

r = Rig(); r.snap["gateway_mac"] = "da:a1:19:00:00:01"; r.snap["neighbors4"][GW] = "da:a1:19:00:00:01"
st, ev, _ = r.step(); show("6 randomized gateway MAC", st, ev); assert st["hardware"] == "warn"

r = Rig(); r.step(); r.snap["adapter"]["dns4"] = ["192.168.1.66"]
st, ev, _ = r.step(); show("7 DNS changed mid-session", st, ev); assert st["settings"] == "alert"

r = Rig(); r.step(); r.snap["adapter"]["dns6"] = ["fe80::bad%12"]
st, ev, _ = r.step(); show("8 mitm6: IPv6 DNS appears", st, ev); assert st["ipv6"] == "alert"

r = Rig(); r.snap["adapter"]["dns6"] = ["fe80::bad%12"]
st, ev, _ = r.step(); show("9 IPv6 DNS w/o router at start", st, ev); assert st["ipv6"] == "warn"

r = Rig(); r.snap["wifi_scan"]["networks"].append({"ssid": "CoffeeShop", "auth": "Open", "bssids": [{"bssid": "00:13:37:aa:bb:cc"}]})
st, ev, _ = r.step(); show("10 evil twin open copy nearby", st, ev); assert st["wifi"] == "alert"

known = {}
r = Rig(known); r.step()
r2 = Rig(known); r2.snap["wifi"]["auth"] = "Open"; r2.snap["wifi_scan"]["networks"][0]["auth"] = "Open"
st, ev, _ = r2.step(); show("11 known WPA2 network now open", st, ev); assert st["history"] == "alert"

r3 = Rig(known); st, ev, _ = r3.step(); show("12 return visit, same", st, ev); assert st["history"] == "ok"

r = Rig(); r.web.tls_ok = False
st, ev, _ = r.step(); show("13 TLS cert untrusted", st, ev); assert st["https"] == "alert"
r = Rig(); r.web.tls_issuer = "Securly Inc"
st, ev, _ = r.step(); show("14 TLS inspection (filter)", st, ev); assert st["https"] == "warn"
r = Rig(); r.web.dns_wrong = [("dns.google", ["10.0.0.5"])]
st, ev, _ = r.step(); show("15 DNS wrong answers", st, ev); assert st["dns"] == "alert"
r = Rig(); r.web.portal = "portal"
st, ev, _ = r.step(); show("16 captive portal", st, ev); assert st["https"] == "unknown" and r.e.overall() == "ok"
r = Rig(); r.snap["wifi"] = None; r.snap["net_key"] = "wired:Ethernet:192.168.1.1:"
st, ev, _ = r.step(); show("17 wired", st, ev); assert st["wifi"] == "off"
r = Rig(); r.snap["net_key"] = None
st, ev, _ = r.step(); show("18 disconnected", st, ev)
r = Rig(); r.snap["wifi"] = None; r.snap["wifi_error"] = "location"
st, ev, _ = r.step(); show("19 location blocked", st, ev); assert st["wifi"] == "unknown"
print("ALL OK")
