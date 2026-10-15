# ARP Watch

A lightweight tool that watches your ARP table and alerts you when the MAC address behind an IP changes, which is a common sign of ARP spoofing / man-in-the-middle activity.

When it starts, it records the MAC address for each watched IP as a baseline. It then polls `arp -a` on an interval and pops up an alert if any of those IPs start answering from a different MAC.

## Versions

| File | Platform | Type |
|---|---|---|
| `arp_watch_gui.py` | Windows | GUI with Start/Stop buttons (buildable to `.exe`) |
| `arp_watch_windows.py` | Windows | Command line |
| `arp_watch.py` | Linux (Ubuntu) | Command line |

All three use only the Python standard library.

## Features

- Watches the **default gateway** (recommended), a **specific IP**, or **every entry** in the ARP table
- Compares MACs **per IP**, so table order and newly discovered devices don't cause false alarms
- Pings the target each cycle to keep its ARP entry fresh
- Alerts once per change with the original, previous, and current MAC
- Separately flags a MAC that **reverts** to the original
- Optional log file (CLI) or exportable log (GUI)

## Windows GUI

### Download

Grab `ArpWatch.exe` from the [Releases](../../releases) page and run it. No install needed.

> Windows Defender / SmartScreen may warn about an unsigned executable. That's common for PyInstaller builds. If you'd rather not trust a binary, build it yourself (below) or run the `.py` directly.

### Run from source

```bat
python arp_watch_gui.py
```

### Build the exe yourself

Requires Python 3.8+ on PATH. Double-click `build_exe.bat`, or run:

```bat
python -m pip install pyinstaller
python -m PyInstaller --onefile --windowed --name ArpWatch arp_watch_gui.py
```

Output: `dist\ArpWatch.exe`

### Using it

1. Choose what to watch: default gateway, a specific IP, or all entries.
2. Set the check interval in seconds.
3. Click **Start**. The current MACs become the baseline.
4. Changed rows turn **red** and reverted rows turn **yellow**. A beep and an always-on-top pop-up fire on each change.
5. Click **Stop** to end monitoring. Use **Export log...** to save the session log.

## Windows CLI

```bat
python arp_watch_windows.py                    :: watch default gateway
python arp_watch_windows.py --ip 192.168.1.1   :: watch a specific IP
python arp_watch_windows.py --all              :: watch all dynamic entries
python arp_watch_windows.py --interval 2 --log arp_watch.log
```

Run it with `pythonw.exe` instead of `python.exe` to hide the console window. To start it at login, create a Task Scheduler task with an **At log on** trigger that runs in your user session (not as SYSTEM), or the pop-ups won't appear.

## Linux CLI (Ubuntu)

```bash
sudo apt install net-tools zenity libnotify-bin
python3 arp_watch.py                     # watch default gateway
python3 arp_watch.py --ip 192.168.1.1    # watch a specific IP
python3 arp_watch.py --all               # watch all entries
python3 arp_watch.py --interval 2 --log arp_watch.log
```

Run it as your normal desktop user, not with `sudo`, so the notifications and pop-ups can reach your session. If zenity isn't installed, it falls back to a tkinter pop-up.

## Options (CLI)

| Option | Description | Default |
|---|---|---|
| `--ip ADDR` | Watch a specific IPv4 address | default gateway |
| `--all` | Watch every entry in the ARP table | off |
| `--interval N` | Seconds between checks | `5` |
| `--log FILE` | Append events to a log file | none |

## Limitations

This is a lightweight detection aid, not a full security control.

- **Legitimate changes will trigger it.** Examples: replacing a router, a VRRP/HSRP gateway failover, or a NIC/VM swap.
- **It trusts the baseline.** If the ARP cache is already poisoned when you press Start, the attacker's MAC becomes the baseline.
- **It's polling-based.** A spoof that comes and goes between checks can be missed.
- **It only runs while open.** Nothing is monitored when the app or script isn't running.

For stronger protection, consider `arpwatch` on Linux, or Dynamic ARP Inspection (DAI) with DHCP snooping on managed switches.

## License

[MIT](LICENSE)
