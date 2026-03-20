```
 ██╗  ██╗████████╗ ██████╗ ██╗  ██╗
 ██║ ██╔╝╚══██╔══╝██╔═══██╗╚██╗██╔╝
 █████╔╝    ██║   ██║   ██║ ╚███╔╝
 ██╔═██╗    ██║   ██║   ██║ ██╔██╗
 ██║  ██╗   ██║   ╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
      ARP Network Control Suite  ·  v4.0
           authorized eyes only
```

> *"Power comes from understanding the protocol layer they forgot to secure."*

---

## ▐ WHAT IS KTOX

**KTOx** is a full ARP network control toolkit for authorized penetration testing. Built on top of [KickThemOut](https://github.com/k4m4/kickthemout) by Kamarinakis & Schütz, extended into a complete suite with both a blood-red industrial terminal UI and a cyberpunk CustomTkinter desktop GUI.

Two ways to run. Same engine.

---

## ▐ RUNNING

```bash
# Terminal UI (CLI)
sudo python3 ktox.py

# Desktop GUI
sudo python3 ktox.py --gui
```

Install GUI dependency first if using `--gui`:
```bash
pip3 install customtkinter
```

---

## ▐ MODULES

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  [1]  Kick ONE off              Single-target ARP denial         │
│  [2]  Kick SOME off             Multi-target ARP denial          │
│  [3]  Kick ALL off              All non-gateway hosts            │
│                                                                  │
│  [4]  ARP Cache Poisoner        Bidirectional MITM intercept     │
│  [5]  ARP Flood                 Saturate target ARP cache (DoS)  │
│  [6]  Gratuitous ARP Broadcast  Claim any IP on the segment      │
│                                                                  │
│  [7]  ARP Watch                 Passive conflict monitor         │
│  [8]  Network Scan              Host discovery + vendor table    │
│  [9]  Target Recon              Port scan + MAC/hostname enum    │
│  [0]  ARP Table Snapshot        Dump OS ARP table to loot        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## ▐ RATE & PACKET CAP

All attack modes prompt for two values:

```
Packets/min per target  [default: 6]
Total packet cap        [0 = unlimited]
```

**Rate** controls how frequently each individual target is spoofed — the interval sleep happens per target, so accuracy is maintained regardless of how many hosts you're hitting.

**Packet cap** hard-stops the attack after N total packets sent. Useful for controlled tests where you need a defined burst. Set to `0` for continuous operation until Ctrl+C.

In the GUI, both fields are in the left control panel under `RATE` and `PACKET CAP`.

---

## ▐ MODULE DETAILS

### [1-3] Kick ONE / SOME / ALL
ARP gateway spoofing — tells targets you're the gateway, cutting their connectivity. Configurable rate and packet cap. Re-ARPs cleanly on stop.

### [4] ARP Cache Poisoner — MITM
Bidirectional poison between target and gateway. Traffic routes through your machine. Enable IP forwarding to intercept without dropping:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
Both sides restored on stop.

### [5] ARP Flood — DoS
Hammers a target with randomised ARP replies, saturating its cache. Rate in packets-per-second. Effective against embedded devices and constrained routers.

### [6] Gratuitous ARP Broadcast
Sends unsolicited ARP replies claiming ownership of any IP on the segment. Useful for IP takeover tests and cache poisoning validation.

### [7] ARP Watch
Passive live sniffer. Logs all IP↔MAC mappings and fires an alert whenever a conflict is detected. Run to check if someone else is spoofing the network.

### [8] Network Scan
Full nmap `-sn` host discovery. Table auto-adapts to terminal width — full columns on wide screens, compact 4-column layout on narrow displays. Vendor resolved locally from built-in OUI table (no API, no network required, instant).

### [9] Target Recon
MAC, vendor, hostname lookup + fast nmap `-F -T4` port scan on a single host.

### [0] ARP Table Snapshot
Dumps the OS ARP table (`arp -a`) into a formatted table and writes structured JSON to the session loot file.

---

## ▐ GUI

Launch with `sudo python3 ktox.py --gui`

```
┌─ Left panel ────────────────┐  ┌─ Right panel ──────────────────┐
│  NETWORK                    │  │  HOST TABLE                    │
│  [ ⟳ SCAN ]                 │  │  # │ IP │ MAC │ VENDOR │ ST   │
│                             │  │  ──────────────────────────    │
│  ATTACK MODE                │  │  (click rows to select)        │
│  ○ Kick ONE                 │  │                                │
│  ○ Kick SOME                │  │  OUTPUT LOG                    │
│  ○ Kick ALL                 │  │  [HH:MM:SS]  event text        │
│  ○ MITM Poison              │  │  [HH:MM:SS]  event text        │
│  ○ ARP Flood                │  │  ...                           │
│  ○ Gratuitous ARP           │  └────────────────────────────────┘
│                             │
│  RATE (pkt/min)  [ 6     ]  │
│  PACKET CAP      [ 0     ]  │
│  GARP CLAIM IP   [       ]  │
│  TARGETS         [ 0,1,2 ]  │
│  [ ◎ USE TABLE SELECTION ]  │
│                             │
│  [ ▶ LAUNCH ATTACK       ]  │
│  [ ■ STOP & RE-ARP       ]  │
│                             │
│  PASSIVE / RECON            │
│  [ ⚡ ARP Watch           ]  │
│  [ ◉  Target Recon       ]  │
│  [ ▣  ARP Snapshot       ]  │
└─────────────────────────────┘
```

Table row selection feeds directly into the targets field via `USE TABLE SELECTION`. All events logged live to the output pane and to the session loot file.

---

## ▐ SESSION LOGGING

Every run creates a timestamped log in `ktox_loot/`:

```
ktox_loot/
├── session_20260319_143201.log   ← CLI sessions
└── gui_20260319_144502.log       ← GUI sessions
```

Newline-delimited JSON — parse with `jq`, grep, or any JSON tooling:

```bash
jq 'select(.event == "ARP_CONFLICT")' ktox_loot/session_*.log
```

---

## ▐ REQUIREMENTS

```bash
pip3 install rich scapy python-nmap netifaces

# GUI only
pip3 install customtkinter
```

System `nmap` binary:

```bash
# Debian / Ubuntu
sudo apt install nmap

# Arch
sudo pacman -S nmap

# macOS
brew install nmap libdnet
```

---

## ▐ INSTALL & RUN

```bash
unzip ktox.zip
pip3 install rich scapy python-nmap netifaces
sudo python3 ktox.py          # CLI
sudo python3 ktox.py --gui    # GUI
```

---

## ▐ FILE STRUCTURE

```
ktox/
├── ktox.py        ← entry point + full CLI TUI
├── ktox_gui.py    ← CustomTkinter GUI frontend
├── scan.py        ← nmap network scanner module
├── spoof.py       ← scapy ARP packet engine
├── README.md      ← you are here
└── ktox_loot/     ← created at runtime, session logs written here
```

---

## ▐ COMPATIBILITY

| Platform | Status                      |
|----------|-----------------------------|
| Linux    | ✔ Full support              |
| macOS    | ✔ With libdnet + brew nmap  |
| Windows  | ✖ Not supported             |

Python 3.8+ required.

---

## ▐ DISCLAIMER

KTOx is intended for **authorized security testing only** — on networks and devices you own or have explicit written permission to test. Unauthorized use against third-party networks is illegal.

The authors accept no liability for misuse.

---

## ▐ CREDITS

ARP engine based on [KickThemOut](https://github.com/k4m4/kickthemout) by
**Nikolaos Kamarinakis** ([@k4m4](https://github.com/k4m4)) &
**David Schütz** ([@xdavidhu](https://github.com/xdavidhu))

KTOx extended by **[wickednull](https://github.com/wickednull)**

---

```
▐████████████████████████████████████████████████████████████████▌
  KTOx v4.0  ·  ARP Network Control Suite  ·  github/wickednull
▐████████████████████████████████████████████████████████████████▌
```
