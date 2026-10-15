import sys, os, ipaddress
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from arpwatch import pathmon as P, scanner as S, winapi as W
P.rdns = lambda ip, timeout=1.5: ""
path = ["10.1.1.1", "10.0.0.1", "10.2.2.1", "10.2.2.50"]
state = {"path": path, "down": False}
def probe(ip, ttl=128, timeout_ms=1000):
    p = state["path"]
    if state["down"]: return None, None, None
    if ttl >= len(p): return W.IP_SUCCESS, ip, 2
    return W.IP_TTL_EXPIRED_TRANSIT, p[ttl-1], 1
net = ipaddress.IPv4Network("10.1.1.0/24")
t = P.Target("10.2.2.50")
for i in range(3):
    P.run_target(t, "10.1.1.1", net, {}, probe); print(t.status, t.summary)
print(P.format_hops(t.hops))
P.run_target(t, "10.1.1.1", net, {}, probe); print(t.status, t.summary); assert t.status=="ok"
state["path"] = ["10.1.1.1", "10.0.0.1", "10.9.9.9", "10.2.2.1", "10.2.2.50"]
ev = P.run_target(t, "10.1.1.1", net, {}, probe); print(t.status, t.summary, [e['title'] for e in ev]); assert t.status=="alert"
state["path"] = path; P.run_target(t, "10.1.1.1", net, {}, probe); print(t.status, t.summary)
state["down"] = True; P.run_target(t, "10.1.1.1", net, {}, probe); print(t.status, t.summary); assert t.status=="alert"
state["down"] = False
state["path"] = ["10.1.1.66", "10.1.1.1", "10.0.0.1", "10.2.2.1", "10.2.2.50"]
P.run_target(t, "10.1.1.1", net, {"10.1.1.66": "b8:27:eb:00:00:01"}, probe); print(t.status, t.details)
for spec in ["192.168.1.0/24", "10.0.0.10-50", "10.0.0.10-10.0.0.12", "10.0.0.5", "10.0.0.0/16", "local", "bad"]:
    ips, err = S.parse_targets(spec, ipaddress.IPv4Network("192.168.5.0/24"))
    print(spec, len(ips), ips[:2], err)
print("OK")
