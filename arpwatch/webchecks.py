"""Internet-facing checks: captive portal, HTTPS interception, DNS tampering.
All use the standard library and a handful of small requests."""

import hashlib
import http.client
import secrets
import socket
import ssl

PORTAL_HOST = "www.msftconnecttest.com"
PORTAL_PATH = "/connecttest.txt"
PORTAL_BODY = "Microsoft Connect Test"

TLS_HOSTS = ["www.google.com", "www.microsoft.com", "www.cloudflare.com"]

# Organizations that operate public certificate authorities. A certificate issued
# by anything else for these big sites means something re-signed the connection.
PUBLIC_CA_ORGS = [
    "digicert", "let's encrypt", "google trust services", "sectigo", "comodo", "globalsign",
    "microsoft", "amazon", "entrust", "godaddy", "starfield", "identrust", "cloudflare",
    "baltimore", "apple", "ssl corporation", "ssl.com", "certainly", "buypass", "harica",
    "actalis", "quovadis", "thawte", "geotrust", "rapidssl", "zerossl", "usertrust",
    "internet security research group",
]

# Hostnames whose correct IPv4 answers never change.
DNS_FIXED = {
    "one.one.one.one": {"1.1.1.1", "1.0.0.1"},
    "dns.google": {"8.8.8.8", "8.8.4.4"},
}


def captive_portal(timeout=5):
    """'online', 'portal', or 'offline'."""
    try:
        c = http.client.HTTPConnection(PORTAL_HOST, 80, timeout=timeout)
        c.request("GET", PORTAL_PATH, headers={"User-Agent": "ArpWatch"})
        r = c.getresponse()
        body = r.read(512).decode("utf-8", "ignore")
        c.close()
        if r.status == 200 and body.strip().startswith(PORTAL_BODY):
            return "online"
        return "portal"
    except (OSError, http.client.HTTPException):
        return "offline"


def _org(name_tuple):
    for rdn in name_tuple or ():
        for k, v in rdn:
            if k == "organizationName":
                return v
    for rdn in name_tuple or ():
        for k, v in rdn:
            if k == "commonName":
                return v
    return "unknown"


def tls_check(host, timeout=6):
    """{'host', 'ok', 'issuer', 'public_ca', 'fingerprint', 'error'}"""
    res = {"host": host, "ok": False, "issuer": None, "public_ca": None,
           "fingerprint": None, "error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                der = s.getpeercert(binary_form=True)
        res["ok"] = True
        res["issuer"] = _org(cert.get("issuer"))
        res["public_ca"] = any(o in res["issuer"].lower() for o in PUBLIC_CA_ORGS)
        res["fingerprint"] = hashlib.sha256(der).hexdigest()
    except ssl.SSLCertVerificationError as e:
        res["error"] = "certificate not trusted: " + (e.verify_message or str(e))
    except (OSError, ssl.SSLError) as e:
        res["error"] = "connection failed: " + str(e)
        res["ok"] = None   # couldn't test (not the same as a bad certificate)
    return res


def dns_check():
    """{'wrong': [(host, answers)], 'failed': [host], 'nx_hijack': bool|None}"""
    out = {"wrong": [], "failed": [], "nx_hijack": None}
    for host, good in DNS_FIXED.items():
        try:
            answers = {a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)}
        except OSError:
            out["failed"].append(host)
            continue
        if not answers <= good:
            out["wrong"].append((host, sorted(answers)))
    # A random name that cannot exist: a normal resolver says "no such domain".
    probe = "aw-" + secrets.token_hex(8) + ".com"
    try:
        socket.getaddrinfo(probe, None, socket.AF_INET)
        out["nx_hijack"] = True
    except socket.gaierror:
        out["nx_hijack"] = False
    except OSError:
        pass
    return out
