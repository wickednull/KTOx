<div align="center">

<!-- BANNER IMAGE - Replace with your actual banner image -->
<img src="https://raw.githubusercontent.com/wickednull/KTOx/main/assets/banner.png" alt="KTOx Banner" width="100%"/>

<br/>

<!-- TITLE -->
# ▐ K T O X ▌

### ARP Network Control Suite · v5.0 · authorized eyes only

<br/>

<!-- BADGES -->
![Python](https://img.shields.io/badge/Python-3.8%2B-red?style=for-the-badge&logo=python&logoColor=white&color=8B0000)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-red?style=for-the-badge&logo=linux&logoColor=white&color=8B0000)
![License](https://img.shields.io/badge/License-GPL--3.0-red?style=for-the-badge&color=8B0000)
![Version](https://img.shields.io/badge/Version-5.0-red?style=for-the-badge&color=8B0000)
![Status](https://img.shields.io/badge/Status-Active-red?style=for-the-badge&color=8B0000)

<br/>

![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-darkred?style=flat-square&color=5a0000)
![Rich](https://img.shields.io/badge/Rich-TUI-darkred?style=flat-square&color=5a0000)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-GUI-darkred?style=flat-square&color=5a0000)
![nmap](https://img.shields.io/badge/nmap-required-darkred?style=flat-square&color=5a0000)
![Root](https://img.shields.io/badge/Requires-Root-darkred?style=flat-square&color=5a0000)

<br/>

> *"Power comes from understanding the protocol layer they forgot to secure."*

<br/>

</div>

---

<div align="center">

```
 ██╗  ██╗████████╗ ██████╗ ██╗  ██╗
 ██║ ██╔╝╚══██╔══╝██╔═══██╗╚██╗██╔╝
 █████╔╝    ██║   ██║   ██║ ╚███╔╝
 ██╔═██╗    ██║   ██║   ██║ ██╔██╗
 ██║  ██╗   ██║   ╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

</div>

---

## ⚡ What is KTOx?

**KTOx** is a complete ARP network control and educational toolkit for authorized penetration testing and network defense. It covers the full attack spectrum — from active ARP exploitation to passive monitoring, hardening, and baselining.

Designed to teach how ARP-based attacks work and how to defend against them.

**Two interfaces:**
- `sudo python3 ktox.py` — Blood-red industrial terminal TUI powered by Rich
- `sudo python3 ktox.py --gui` — Cyberpunk CustomTkinter desktop GUI

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/wickednull/KTOx
cd KTOx

# Install dependencies
pip3 install rich scapy python-nmap netifaces customtkinter
sudo apt install nmap

# Run CLI
sudo python3 ktox.py

# Run GUI
sudo python3 ktox.py --gui

# If using a venv with sudo
sudo ./venv/bin/python3 ktox.py --gui
```

---

## 🔴 Offensive Modules

<div align="center">

| Key | Module | Description |
|-----|--------|-------------|
| `1` | **Kick ONE off** | Single-target ARP denial — cuts one device off the network |
| `2` | **Kick SOME off** | Multi-target ARP denial — select specific hosts |
| `3` | **Kick ALL off** | Spoof every non-gateway host simultaneously |
| `4` | **ARP Cache Poisoner** | Bidirectional MITM — intercept traffic between target and gateway |
| `5` | **ARP Flood** | Saturate a single target's ARP cache with randomised entries |
| `6` | **ARP Reply Storm** | Flood the entire broadcast domain — degrades the whole LAN |
| `7` | **Gratuitous ARP** | Broadcast IP ownership claim to all hosts on segment |
| `8` | **Gateway DoS** | Flood the router directly — takes down routing for the whole LAN |
| `9` | **ARP Cage** | Full isolation — poison target's view of every peer simultaneously |

</div>

### How ARP Poisoning Works

```
Normal ARP:
  Device A  →  BROADCAST:  "Who has 192.168.1.1?"
  Gateway   →  Device A:   "192.168.1.1 is at AA:BB:CC:DD:EE:FF"

Poisoned ARP (KTOx MITM):
  KTOx  →  Device A:   "192.168.1.1 is at 11:22:33:44:55:66"  ← lie
  KTOx  →  Gateway:    "192.168.1.50 is at 11:22:33:44:55:66" ← lie
  # All traffic now flows through KTOx
```

> ⚠️ For MITM mode, enable IP forwarding to avoid dropping intercepted packets:
> ```bash
> echo 1 > /proc/sys/net/ipv4/ip_forward
> ```

---

## 🔍 Recon Modules

<div align="center">

| Key | Module | Description |
|-----|--------|-------------|
| `A` | **ARP Request Scan** | Stealth host discovery via raw ARP — faster than nmap, mostly invisible to IDS |
| `B` | **Target Recon** | MAC vendor lookup + hostname + fast nmap `-F -T4` port scan |
| `C` | **MAC Spoof** | Change interface MAC before attacks — real hardware ID never appears in logs |

</div>

---

## 🛡️ Defensive Modules

<div align="center">

| Key | Module | Description |
|-----|--------|-------------|
| `D` | **ARP Watch** | Passive sniffer — alerts on any IP↔MAC mapping conflict in real time |
| `F` | **Live ARP Diff** | Polls OS ARP table on a timer, diffs each snapshot — catches silent poisoning |
| `G` | **Rogue Device Detector** | Alerts when a new MAC joins the network that wasn't in the baseline |
| `H` | **ARP Hardening** | Applies static ARP entries for all hosts — prevents poisoning at OS level |
| `I` | **Baseline Export** | Exports trusted JSON snapshot of network state for future comparison |
| `J` | **ARP Snapshot** | Dumps current OS ARP table to loot file |
| `K` | **Network Scan** | Full host discovery — IP, MAC, vendor, hostname |

</div>

### Defense Matrix

<div align="center">

| Defense | Stops DoS | Stops MITM | Stops Flood | Stops Storm |
|---------|-----------|------------|-------------|-------------|
| Static ARP entries | ✅ | ✅ | ❌ | ✅ |
| Dynamic ARP Inspection | ✅ | ✅ | ✅ | ✅ |
| ARP Watch / Diff | 🔍 detect | 🔍 detect | 🔍 detect | 🔍 detect |
| VPN / Encryption | ❌ | ✅ data | ❌ | ❌ |
| VLAN Segmentation | ✅ | ✅ | ✅ | ✅ |
| Port Security | ❌ | ❌ | ✅ | ✅ |

</div>

---

## ⚙️ Rate & Packet Cap

All attack modes prompt for two values:

```
Packets/min per target  →  rate control (default: 6)
Total packet cap        →  hard stop after N packets (0 = unlimited)
```

Rate is **per-target** — interval sleep happens per individual packet so accuracy is maintained regardless of target count.

---

## 📁 File Structure

```
KTOx/
├── ktox.py         ← entry point + full CLI TUI (all 20 modules)
├── ktox_gui.py     ← CustomTkinter GUI frontend
├── scan.py         ← nmap network scanner module
├── spoof.py        ← scapy ARP packet engine
├── README.md       ← you are here
└── ktox_loot/      ← created at runtime
    ├── session_TIMESTAMP.log      ← CLI session logs (NDJSON)
    ├── gui_TIMESTAMP.log          ← GUI session logs
    ├── baseline_TIMESTAMP.json    ← network baselines
    └── arp_harden.sh              ← generated hardening script
```

---

## 📊 Session Logging

Every run writes a timestamped log to `ktox_loot/` in newline-delimited JSON:

```json
{"ts": "2026-03-20T14:32:01", "event": "SCAN_COMPLETE",  "data": {"count": 9}}
{"ts": "2026-03-20T14:33:10", "event": "MITM_START",     "data": {"target": "192.168.1.42"}}
{"ts": "2026-03-20T14:35:44", "event": "ARP_DIFF_CHANGE","data": {"ip": "192.168.1.1", "old_mac": "aa:bb:cc:dd:ee:ff", "new_mac": "11:22:33:44:55:66"}}
{"ts": "2026-03-20T14:40:01", "event": "ROGUE_DETECTED", "data": {"ip": "192.168.1.99", "mac": "de:ad:be:ef:00:01"}}
```

Parse with `jq`:
```bash
# Find all ARP conflicts
jq 'select(.event == "ARP_DIFF_CHANGE")' ktox_loot/session_*.log

# Find rogue devices
jq 'select(.event == "ROGUE_DETECTED")' ktox_loot/session_*.log
```

---

## 🖥️ Compatibility

<div align="center">

| Platform | CLI | GUI | Notes |
|----------|-----|-----|-------|
| **Kali Linux** | ✅ | ✅ | Primary platform |
| **Debian / Ubuntu** | ✅ | ✅ | Full support |
| **Arch Linux** | ✅ | ✅ | Full support |
| **Raspberry Pi** | ✅ | ✅ | Tested on Kali ARM |
| **macOS** | ✅ | ✅ | Requires libdnet + brew nmap |
| **Windows** | ❌ | ❌ | Not supported |

</div>

Python **3.8+** required. Must be run as **root**.

---

## 📦 Dependencies

```bash
pip3 install rich scapy python-nmap netifaces customtkinter
```

| Package | Purpose |
|---------|---------|
| `scapy` | ARP packet crafting and sending |
| `rich` | Terminal UI — tables, panels, spinners |
| `python-nmap` | Network scanning and port enumeration |
| `netifaces` | Gateway and interface detection |
| `customtkinter` | Desktop GUI framework |
| `nmap` (system) | Required binary for scanning |

---

## ⚠️ Disclaimer

KTOx is an **educational tool** intended for **authorized security testing only** — on networks and devices you own or have explicit written permission to test.

It is designed to demonstrate how ARP-based attacks work and how to defend against them. Unauthorized use against third-party networks is illegal under the Computer Fraud and Abuse Act, Computer Misuse Act, and equivalent legislation worldwide.

**The author accepts no liability for misuse.**

---

## 🙏 Credits

ARP engine based on [KickThemOut](https://github.com/k4m4/kickthemout) by
[Nikolaos Kamarinakis](https://github.com/k4m4) & [David Schütz](https://github.com/xdavidhu)

Extended and rebuilt by **[wickednull](https://github.com/wickednull)**

---

<div align="center">

```
▐████████████████████████████████████████████████████████████████▌
  KTOx v5.0  ·  ARP Network Control Suite  ·  github/wickednull
▐████████████████████████████████████████████████████████████████▌
```

![GitHub stars](https://img.shields.io/github/stars/wickednull/KTOx?style=for-the-badge&color=8B0000)
![GitHub forks](https://img.shields.io/github/forks/wickednull/KTOx?style=for-the-badge&color=8B0000)
![GitHub issues](https://img.shields.io/github/issues/wickednull/KTOx?style=for-the-badge&color=8B0000)

</div>
