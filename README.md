# QuickSentry

A lightweight Windows tool that watches the network you're on and warns you about **man-in-the-middle (MITM) attacks**. It's built mainly for laptops on **public Wi-Fi** (coffee shops, hotels, airports). It also includes a path monitor and a subnet scanner for investigating networks you manage.

It runs from a single `.exe` with no install, and it can run straight from a USB flash drive.

> **Detection, not protection.** QuickSentry tells you when a network looks suspicious. Your traffic is actually protected by a **VPN** and by HTTPS websites. Use one on public Wi-Fi either way.

---

## Quick start

1. Download `QuickSentry.exe` from the [Releases](../../releases) page.
2. Run it. Monitoring starts automatically.
3. Check the colored banner at the top:

| Banner | Meaning | What to do |
|---|---|---|
| 🟢 **No signs of attack** | All checks passed. | Nothing. |
| 🟡 **Something looks unusual** | Something is unusual but not clearly an attack. | Read the yellow items. Avoid banking and logins unless you're on a VPN. |
| 🔴 **Possible attack detected** | A strong sign of interception. | Stop sensitive activity, disconnect or turn on a VPN, then read the red items. |

Click any check to see what it found, why it matters, and what to do about it.

Windows may show a SmartScreen warning because the exe isn't code-signed. Click **More info → Run anyway**, or build it yourself (see below).

---

## What it checks

| Check | What it catches |
|---|---|
| **Router identity** | The router's hardware (MAC) address changing while you're connected. This is the classic sign of ARP spoofing. |
| **ARP spoofing signs** | Another device answering with the router's MAC. Works even if spoofing started before you opened the app. |
| **Router hardware** | A "router" whose MAC belongs to a laptop or phone maker, a virtual machine, a Raspberry Pi, known hacking hardware (WiFi Pineapple prefix), or a randomized MAC. |
| **Traffic route** | Whether your traffic passes through another local device before reaching the router (checked with a TTL=1 probe). This is how most MITM tools forward traffic. |
| **Network settings** | The router, DHCP server, or DNS servers changing without a reconnect, which points to a rogue DHCP server. |
| **IPv6 safety** | A new IPv6 router or DNS server appearing, an IPv6 DNS server with no IPv6 router (the mitm6 pattern), or an IPv6 router that's a different device from your router. |
| **Wi-Fi access point** | "Evil twin" hotspots: the same network name broadcast both secured and open, access points with randomized or known-hacking MACs, and open networks. |
| **Compared to last visit** | Changes since your last visit to this network, such as a different router, or a network that used to need a password and is now open. |
| **Internet / sign-in page** | Captive portals (hotel or coffee-shop login pages). HTTPS and DNS checks pause until you've signed in, to avoid false alarms. |
| **HTTPS encryption** | Certificates for major sites that are untrusted or issued by a non-public authority, meaning something is decrypting your HTTPS traffic. |
| **Website lookups (DNS)** | DNS answers that are wrong for names whose correct addresses never change (`one.one.one.one`, `dns.google`). |

Alerts can also show a pop-up, play a sound, and send a tray notification. Each one is logged with a timestamp.

### Response buttons
- **Disconnect Wi-Fi**: leaves the network immediately.
- **Pin router address**: adds a static ARP entry for the router, which blocks ARP spoofing. It needs admin rights (Windows asks), lasts until you unpin or reboot, and QuickSentry offers to remove it when you leave the network. It's disabled while an alert is active, since the current router address could be the attacker's.
- **Reset baseline**: accepts the current state as normal. Use it only when you know why something changed, for example after a router replacement.
- **Save report**: writes a text report of the connection, all checks, devices, path monitor results, scan results, and recent events.

---

## Path Monitor (for networks you manage)

Repeatedly traces the route from this machine to one or more targets, for example a server on the other side of campus.

- It learns the normal path over the first 3 runs. Load-balanced links that alternate between hops are learned as normal.
- After that, it alerts on:
  - a **new device in the path** (with its name and, for local hops, MAC and maker)
  - a **changed path length**
  - **latency jumps** and **packet loss**
  - the **connection going down**
  - **traffic passing through a local device before the router**
- For targets on the same subnet, it also watches the target's MAC address.
- **Accept current path** marks a legitimate change as the new normal.

**Limit:** a device that routes traffic shows up as a hop. A fully transparent inline device (a bridge or network tap) does not show up in a traceroute. You may only see its side effects (added latency or loss). Firewalls that block ICMP show up as `*` hops.

## Network Scan

Sweeps an IP range (`192.168.1.0/24`, `10.1.2.10-10.1.2.80`, `10.1.2.10-80`; max 1024 addresses). It lists each device with its name, MAC, and maker, and flags:
- **duplicate MACs**, especially devices sharing the router's MAC
- randomized MACs, virtual machines, Raspberry Pis, and known hacking hardware

Devices that block ping still appear if they answer ARP (same subnet only). Results export to CSV. **Only scan networks you're authorized to scan.** On public Wi-Fi, client isolation usually hides other devices.

---

## Running from a USB flash drive

Copy `QuickSentry.exe` to the drive, plug the drive in, and double-click the exe.

- **Windows will not auto-launch it.** Windows has blocked AutoRun from USB drives since Windows 7 because it was a major malware vector. Every legitimate portable tool has to be launched by hand.
- **Portable mode turns on automatically** on removable drives. Settings, remembered networks, logs, and reports go to an `QuickSentry-data` folder on the drive, and nothing is written to the PC.
- Some large USB drives report themselves as fixed disks. If you don't see "Portable mode: ON" under Settings, create an empty `portable.txt` file next to the exe.
- Before plugging a USB drive into an organization's computers, check its policy. Many organizations block or log USB drives.

---

## Data and privacy

Everything stays on your computer (or the USB drive). Nothing is sent anywhere except the small test requests the checks themselves make:
- `www.msftconnecttest.com`, to detect sign-in pages
- `www.google.com`, `www.microsoft.com`, `www.cloudflare.com`, to check HTTPS certificates
- DNS lookups for `one.one.one.one`, `dns.google`, and one random made-up name

QuickSentry remembers the names of networks you've joined, along with their router MACs and access point IDs, so it can compare visits. Clear this under **Settings → Forget remembered networks**.

Data locations: `%APPDATA%\QuickSentry`, or `QuickSentry-data` next to the exe in portable mode.

---

## Building the exe yourself

Requires Python 3.10+ on PATH.

```bat
build_exe.bat
```
or manually:
```bat
python -m pip install -r requirements.txt
python -m PyInstaller --onefile --windowed --clean --name QuickSentry --icon assets/QuickSentry.ico --hidden-import pystray._win32 quicksentry_gui.py
```
Output: `dist\QuickSentry.exe`. Pushing a tag such as `v2.0.0` also builds it on GitHub (see `.github/workflows/build.yml`).

Run from source with `python quicksentry_gui.py`. Without `pystray`/`pillow` installed, everything works except the tray icon.

---

## Troubleshooting

- **"Windows is blocking Wi-Fi details."** Windows 11 requires location access to read Wi-Fi information. Turn on **Settings → Privacy & security → Location**, plus **Let desktop apps access your location**.
- **Something doesn't look right.** Click **Settings → Run diagnostics**. It tests every data source on your machine and saves a report you can share.
- **Non-English Windows.** The Wi-Fi and `ipconfig` readers expect English output. The ARP, route, and ping checks use the Windows API and work in any language.
- **Constant yellow "HTTPS inspection" on a work or school network.** This is expected where a web filter (Securly, Lightspeed, Fortinet, Zscaler, and others) inspects HTTPS. It drops to Info on later visits to the same network.

## Limitations

- **Polling-based.** An attack that starts and stops between checks can be missed. The default interval is 5 seconds.
- **The first visit to a network has no history.** If a network is already compromised when you join, only the checks that don't need a baseline can catch it: duplicate MAC, router hardware, traffic route, evil twin, HTTPS, DNS, and the mitm6 pattern.
- **Legitimate changes trigger alerts too.** Examples: router replacement, failover, different branches of a chain, phone hotspots. Every alert explains the normal explanations.
- **A transparent bridge or tap is invisible** to everything here.
- **Windows only** for the GUI. `tools/arp_monitor_linux.py` is a minimal Linux command-line version.

## Project layout

```
quicksentry_gui.py      Entry point (Windows GUI)
quicksentry/
  engine.py             Detection logic (all checks)
  sysinfo.py            Reads ipconfig / netsh / neighbor table into a snapshot
  winapi.py             Windows API calls (ARP table, routes, ICMP) with fallbacks
  webchecks.py          Sign-in page, HTTPS, DNS checks
  pathmon.py            Path monitor / traceroute
  scanner.py            Subnet scan
  oui.py, oui_data.py   Offline MAC vendor database (IEEE)
  actions.py            Disconnect, pin, reports, diagnostics
  storage.py            Settings, remembered networks, portable mode
  tray.py, gui.py       User interface
tools/
  arp_monitor_linux.py  Minimal Linux command-line ARP monitor
  arp_monitor_windows.py  Minimal Windows command-line ARP monitor
tests/                  Tests with sample Windows output
```

Run tests: `python tests/test_parsers.py`, `python tests/test_engine.py`, `python tests/test_path.py`.

## Acknowledgements

Inspired by classic ARP monitoring tools such as [arpwatch](https://en.wikipedia.org/wiki/Arpwatch) (LBNL) and XArp. QuickSentry was previously named "ARP Watch" and was renamed to avoid confusion with arpwatch.

## License

[MIT](LICENSE). MAC vendor data comes from the IEEE OUI registry, via the netaddr project.
