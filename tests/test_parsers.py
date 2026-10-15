"""Parser tests against sample English-Windows output. Run: python tests/test_parsers.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from samples import IPCONFIG, WLAN_IF, WLAN_NETS, WLAN_LOCATION, ARP_A
from arpwatch import sysinfo, winapi, oui

a = sysinfo.parse_ipconfig(IPCONFIG)["Wi-Fi"]
assert a["gateways4"] == ["192.168.1.1"] and a["gateways6"] == ["fe80::1%12"]
assert a["dns4"] == ["192.168.1.1", "8.8.8.8"] and a["dns6"] == []   # fec0 placeholder dropped
assert a["dhcp_server"] == "192.168.1.1" and a["mask"] == "255.255.255.0"
assert not sysinfo.parse_ipconfig(IPCONFIG)["Ethernet"]["connected"]
w = sysinfo.parse_wlan_interfaces(WLAN_IF)["interfaces"][0]
assert w["ssid"] == "CoffeeShop" and w["bssid"] == "00:1a:1e:11:22:33" and w["auth"] == "WPA2-Personal"
nets = sysinfo.parse_wlan_networks(WLAN_NETS)["networks"]
assert [n["auth"] for n in nets if n["ssid"] == "CoffeeShop"] == ["WPA2-Personal", "Open"]
assert sysinfo.parse_wlan_interfaces(WLAN_LOCATION) == {"error": "location"}
rows = winapi.parse_arp_a(ARP_A)
assert rows[0]["ifindex"] == 12 and len(rows) == 4
assert oui.category("08:00:27:00:00:01") == "virtual" and oui.category("da:00:00:00:00:01") == "randomized"
assert not oui.is_usable("ff:ff:ff:ff:ff:ff") and not oui.is_usable("01:00:5e:00:00:16")
print("ALL OK")
