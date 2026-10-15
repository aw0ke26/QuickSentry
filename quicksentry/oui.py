"""MAC address vendor lookup and classification (offline)."""

import base64
import zlib

_DB = None

# Prefixes worth calling out even though the IEEE name looks harmless.
_SPECIAL = {
    "001337": ("attack_tool", "Orient Power (prefix also used by Hak5 WiFi Pineapple)"),
}

# Vendor keyword -> category. Matched case-insensitively against the IEEE name.
# These are used only to judge whether a *router/gateway* MAC looks normal.
_CATEGORIES = [
    ("attack_tool", ["hak5"]),
    ("virtual", ["vmware", "pcs systemtechnik", "oracle", "parallels", "xensource",
                 "qemu", "virtualbox"]),
    ("sbc", ["raspberry pi"]),
    ("endpoint", ["apple", "samsung electronics", "intel corporate", "liteon", "lite-on",
                  "azurewave", "hon hai", "murata", "xiaomi", "oneplus",
                  "motorola mobility", "microsoft", "dell inc", "lenovo", "hp inc",
                  "chicony", "rivet networks", "espressif"]),
]


def _load():
    global _DB
    if _DB is None:
        from .oui_data import DATA
        raw = zlib.decompress(base64.b85decode("".join(DATA))).decode("utf-8", "replace")
        _DB = dict(line.split("\t", 1) for line in raw.splitlines() if "\t" in line)
    return _DB


def normalize(mac):
    """Return aa:bb:cc:dd:ee:ff or '' if invalid."""
    if not mac:
        return ""
    h = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(h) != 12:
        return ""
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac):
    """True for randomized / software-assigned MACs (2nd bit of first octet)."""
    mac = normalize(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


def is_multicast(mac):
    mac = normalize(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 0x01)


def is_usable(mac):
    """Filter out empty, broadcast, multicast and all-zero MACs."""
    mac = normalize(mac)
    return bool(mac) and mac != "00:00:00:00:00:00" and not is_multicast(mac)


def vendor(mac):
    mac = normalize(mac)
    if not mac:
        return None
    if is_locally_administered(mac):
        return "Randomized / private MAC"
    prefix = mac.replace(":", "")[:6].upper()
    if prefix in _SPECIAL:
        return _SPECIAL[prefix][1]
    try:
        return _load().get(prefix)
    except Exception:
        return None


def category(mac):
    """One of: randomized, attack_tool, virtual, sbc, endpoint, unknown, network."""
    mac = normalize(mac)
    if not mac:
        return "unknown"
    if is_locally_administered(mac):
        return "randomized"
    prefix = mac.replace(":", "")[:6].upper()
    if prefix in _SPECIAL:
        return _SPECIAL[prefix][0]
    v = vendor(mac)
    if not v:
        return "unknown"
    lv = v.lower()
    for cat, words in _CATEGORIES:
        if any(w in lv for w in words):
            return cat
    return "network"
