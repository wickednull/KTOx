![image](https://github.com/user-attachments/assets/65cc3ab8-23f4-49a7-abc6-07bfd31a792e)

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

**KTOx** is a full ARP network control toolkit for authorized penetration testing. What started as a polished TUI wrapper around [KickThemOut](https://github.com/k4m4/kickthemout) has grown into a complete suite — covering everything from denial-of-service spoofing and bidirectional MITM intercept to ARP cache flooding, gratuitous broadcast, and passive conflict monitoring.

Blood-red industrial terminal UI. Session logging to structured loot files. No noise.

---

## ▐ MODULES

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  [1]  Kick ONE off              Single-target ARP denial         │
│  [2]  Kick SOME off             Multi-target ARP denial          │
│  [3]  Kick ALL off              Broadcast ARP flood (all hosts)  │
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

## ▐ MODULE DETAILS

### [1-3] Kick ONE / SOME / ALL
Classic ARP gateway spoofing inherited from KickThemOut. Intercepts target's traffic by telling it you're the gateway. Configurable packets-per-minute rate. Cleans up with re-ARP on exit.

### [4] ARP Cache Poisoner — MITM
Bidirectional poison. Tells the target you're the gateway AND tells the gateway you're the target. Traffic routes through your machine. Enable IP forwarding to intercept without dropping:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
Both ARP tables are restored cleanly on Ctrl+C.

### [5] ARP Flood — DoS
Hammers a target with randomised ARP reply packets — each with a unique fake IP and MAC — saturating its ARP cache. Effective against embedded devices, cheap switches, and hosts with constrained ARP table sizes. Rate is configurable in packets-per-second.

### [6] Gratuitous ARP Broadcast
Sends unsolicited ARP replies to the broadcast address claiming ownership of any IP you specify. Forces cache updates on every listening host on the segment. Useful for IP takeover tests, failover/HSRP testing, and cache poisoning validation. Repeat count and interval are configurable.

### [7] ARP Watch
Passive live sniffer. Logs every new IP↔MAC mapping it sees and fires an alert any time an IP is observed with a different MAC than previously recorded. Useful for detecting existing spoofing activity on the network. All events logged to session file.

### [8] Network Scan
Full host discovery sweep using nmap `-sn`. Displays a rich table with IP, MAC, vendor (via macvendors.co), hostname, and gateway flag.

### [9] Target Recon
Resolves MAC, vendor, and hostname for a target, then runs a fast nmap `-F -T4` port scan. Results displayed in a clean table with open/closed state colouring. All data written to session log.

### [0] ARP Table Snapshot
Dumps the live OS ARP table (`arp -a`) into a formatted terminal table and writes all entries as structured JSON to the session loot file.

---

## ▐ SESSION LOGGING

Every run creates a timestamped `.log` file in `ktox_loot/`:

```
ktox_loot/
└── session_20250319_143201.log
```

All events are written as newline-delimited JSON:

```json
{"ts": "2025-03-19T14:32:01", "event": "SCAN_COMPLETE", "data": {"count": 8}}
{"ts": "2025-03-19T14:33:10", "event": "MITM_START",    "data": {"target": "192.168.1.42"}}
{"ts": "2025-03-19T14:35:44", "event": "ARP_CONFLICT",  "data": {"ip": "192.168.1.1", "old_mac": "...", "new_mac": "..."}}
```

Parse with `jq`, grep, or any JSON tooling.

---

## ▐ REQUIREMENTS

```bash
pip3 install rich scapy python-nmap netifaces
```

System `nmap` binary required:

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
unzip ktox.zip && cd ktox
pip3 install rich scapy python-nmap netifaces
sudo python3 ktox.py
```

Root required. KTOx will detect your interface and gateway automatically on launch, then scan the local network before dropping you into the menu.

---

## ▐ FILE STRUCTURE

```
ktox/
├── ktox.py       ← main TUI + all module logic
├── scan.py       ← nmap network scanner module
├── spoof.py      ← scapy ARP packet engine
├── README.md     ← you are here
└── ktox_loot/    ← created at runtime, session logs written here
```

---

## ▐ COMPATIBILITY

| Platform | Status              |
|----------|---------------------|
| Linux    | ✔ Full support      |
| macOS    | ✔ With libdnet + brew nmap |
| Windows  | ✖ Not supported     |

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
