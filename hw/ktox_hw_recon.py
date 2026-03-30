#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_recon.py — KTOx Recon Engine (Hardware GUI)
#
# All passive and active reconnaissance functions with RaspyJack LCD/GPIO:
#   Network Scan · Target Recon (port scan) · ARP Snapshot
#   ARP Watch · ARP Diff · Rogue Device Detect
#   Baseline Export · MAC Spoof (recon context)
#
# Controls: UP/DOWN scroll · OK select · KEY3 back/stop

import sys, os, time, signal, threading, json

_HW_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT   = os.path.dirname(_HW_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ktox_hw_utils import (
    hw_init, hw_cleanup, push,
    clear_buf, draw_header, draw_status, draw_menu, draw_centered,
    draw_running, draw_result, draw_hosts,
    read_btn, wait_for_btn,
    scan_and_pick, get_iface_and_gateway, get_network_cidr,
    do_scan_hw, resolve_mac,
    install_signal_handlers, make_logger, loot_dir,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL, LCD_W, LCD_H,
)

log = make_logger("recon")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "NET SCAN",
    "TARGET RECON",
    "ARP SNAPSHOT",
    "ARP WATCH",
    "ARP DIFF",
    "ROGUE DETECT",
    "BASELINE EXPORT",
    "< BACK",
]
MENU_COLORS = [
    C["ASH"], C["ASH"], C["STEEL"],
    C["STEEL"], C["STEEL"], C["ORANGE"], C["STEEL"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# ── RECON OPERATIONS ──────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def op_net_scan(iface, network, gw_ip):
    """Full host discovery + display."""
    clear_buf(DRAW)
    draw_header(DRAW, "NET SCAN", color=C["ASH"])
    draw_centered(DRAW, "sweeping...", 50, FONT_MENU, fill=C["STEEL"])
    draw_centered(DRAW, network or iface, 65, FONT_SMALL, fill=C["DIM"])
    push(LCD, IMAGE)

    hosts = do_scan_hw(network)
    log(f"NET_SCAN_DONE hosts={len(hosts)}")

    if not hosts:
        draw_result(DRAW, "NET SCAN", ["no hosts found"], color=C["ORANGE"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, f"HOSTS ({len(hosts)})", color=C["ASH"])
        draw_hosts(DRAW, hosts, sel)
        draw_status(DRAW, "OK:DETAIL KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(hosts)
        elif btn == "DOWN":
            sel = (sel + 1) % len(hosts)
        elif btn in ("OK", "KEY_PRESS"):
            h = hosts[sel]
            detail = [
                f"IP: {h[0]}",
                f"MAC: {(h[1] if len(h)>1 and h[1] else '?')[:17]}",
                f"VND: {(h[2] if len(h)>2 and h[2] else '?')[:16]}",
                f"HST: {(h[3] if len(h)>3 and h[3] else '?')[:16]}",
                f"GW: {'YES' if h[0]==gw_ip else 'no'}",
            ]
            draw_result(DRAW, "HOST DETAIL", detail, color=C["ASH"])
            push(LCD, IMAGE)
            wait_for_btn(["KEY3", "LEFT", "OK"])
        elif btn in ("KEY3", "LEFT"):
            break
        time.sleep(0.05)


def op_target_recon(network, gw_ip):
    """Port scan + service banner grab on a chosen target."""
    try:
        import nmap
    except ImportError:
        draw_result(DRAW, "RECON", ["nmap not installed"], color=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    host = scan_and_pick(LCD, IMAGE, DRAW, None, network,
                         title="RECON TARGET", allow_gw=True)
    if not host:
        return

    target_ip = host[0]
    clear_buf(DRAW)
    draw_header(DRAW, "PORT SCAN", color=C["ASH"])
    draw_centered(DRAW, target_ip, 35, FONT_MENU, fill=C["WHITE"])
    draw_centered(DRAW, "scanning ports...", 52, FONT_SMALL, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        nm     = nmap.PortScanner()
        result = nm.scan(hosts=target_ip, arguments="-sV --top-ports 100 -T4")
        log(f"TARGET_RECON_DONE ip={target_ip}")

        host_data = result.get("scan", {}).get(target_ip, {})
        tcp_ports  = host_data.get("tcp", {})

        open_ports = []
        for port, info in tcp_ports.items():
            if info.get("state") == "open":
                svc  = info.get("name", "")[:8]
                ver  = info.get("version", "")[:6]
                open_ports.append(f"{port}/{svc} {ver}")

        # Save to loot
        out_file = os.path.join(loot_dir(), f"recon_{target_ip.replace('.','_')}.json")
        try:
            with open(out_file, "w") as f:
                json.dump({"ip": target_ip, "ports": open_ports,
                           "full": host_data}, f, indent=2)
        except Exception:
            pass

        # Display
        if not open_ports:
            lines = [target_ip, "no open ports", "saved to loot"]
        else:
            lines = [target_ip, f"{len(open_ports)} open"] + open_ports[:4]

        sel    = 0
        last_t = 0.0
        while True:
            clear_buf(DRAW)
            draw_header(DRAW, f"RECON {target_ip[:10]}", color=C["ASH"])
            all_lines = lines + [f"..saved to loot"]
            draw_menu(DRAW, all_lines, sel,
                      item_colors=[C["WHITE"]] * len(all_lines))
            draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
            push(LCD, IMAGE)

            btn, last_t = read_btn(last_t)
            if btn == "UP":
                sel = max(0, sel - 1)
            elif btn == "DOWN":
                sel = min(len(all_lines) - 1, sel + 1)
            elif btn in ("KEY3", "LEFT"):
                break
            time.sleep(0.05)

    except Exception as e:
        log(f"target_recon error: {e}")
        draw_result(DRAW, "RECON ERR", [str(e)[:20]], color=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])


def op_arp_snapshot(iface, network, gw_ip):
    """Dump current ARP table + scan results to loot."""
    clear_buf(DRAW)
    draw_header(DRAW, "ARP SNAP", color=C["STEEL"])
    draw_centered(DRAW, "scanning...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    hosts = do_scan_hw(network)

    import datetime
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    snap_file = os.path.join(loot_dir(), f"arp_snap_{ts}.json")
    snap_data = [{"ip": h[0], "mac": h[1], "vendor": h[2], "hostname": h[3]}
                 for h in hosts]
    try:
        with open(snap_file, "w") as f:
            json.dump(snap_data, f, indent=2)
        log(f"ARP_SNAP_SAVED file={snap_file}")
        draw_result(DRAW, "ARP SNAP",
                    [f"{len(hosts)} entries", os.path.basename(snap_file)[:18],
                     "saved to loot"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"arp_snapshot error: {e}")
        draw_result(DRAW, "SNAP ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_arp_watch_recon(iface):
    """Passive ARP monitoring — show live ARP table and change alerts."""
    try:
        from scapy.all import sniff, ARP
        import logging as _lg
        _lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)
    except ImportError:
        draw_result(DRAW, "ARP WATCH", ["scapy not found"], color=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    arp_table = {}
    alerts    = []
    stop      = threading.Event()

    def _pkt_handler(pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                msg = f"{ip} {arp_table[ip][:8]}→{mac[:8]}"
                alerts.append(msg)
                log(f"ARP_CHANGE {msg}")
            arp_table[ip] = mac

    def _sniff():
        sniff(iface=iface, filter="arp", prn=_pkt_handler,
              store=0, stop_filter=lambda _: stop.is_set())

    t = threading.Thread(target=_sniff, daemon=True)
    t.start()
    log("ARP_WATCH_START")

    last_t  = 0.0
    elapsed = 0
    t_start = time.time()
    while not stop.is_set():
        elapsed = int(time.time() - t_start)
        clear_buf(DRAW)
        draw_header(DRAW, "ARP WATCH", color=C["STEEL"])
        draw_centered(DRAW, f"seen: {len(arp_table)}",  30, FONT_MENU, fill=C["WHITE"])
        draw_centered(DRAW, f"alerts: {len(alerts)}",   46, FONT_MENU,
                      fill=C["BLOOD"] if alerts else C["GOOD"])
        # Show last alert
        if alerts:
            draw_centered(DRAW, alerts[-1][:20], 62, FONT_SMALL, fill=C["EMBER"])
        draw_centered(DRAW, f"{elapsed}s", 78, FONT_SMALL, fill=C["DIM"])
        draw_status(DRAW, "KEY3: STOP", color=C["DIM"])
        push(LCD, IMAGE)
        btn, last_t = read_btn(last_t)
        if btn in ("KEY3", "LEFT"):
            stop.set()
        time.sleep(0.2)

    t.join(timeout=3)
    log(f"ARP_WATCH_STOP alerts={len(alerts)}")
    draw_result(DRAW, "WATCH DONE",
                [f"{len(alerts)} changes", f"{len(arp_table)} seen"],
                color=C["GOOD"] if not alerts else C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_arp_diff(iface, network):
    """Compare two ARP scans and show what changed."""
    # First scan
    clear_buf(DRAW)
    draw_header(DRAW, "ARP DIFF", color=C["STEEL"])
    draw_centered(DRAW, "SCAN 1...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    snap1 = {h[0]: h[1] for h in do_scan_hw(network)}

    clear_buf(DRAW)
    draw_header(DRAW, "ARP DIFF", color=C["STEEL"])
    draw_centered(DRAW, f"snap1: {len(snap1)}",  35, FONT_MENU, fill=C["WHITE"])
    draw_centered(DRAW, "OK: scan again",          50, FONT_SMALL, fill=C["STEEL"])
    draw_status(DRAW, "OK:SNAP2 KEY3:BACK", color=C["DIM"])
    push(LCD, IMAGE)
    btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
    if btn in ("KEY3", "LEFT"):
        return

    clear_buf(DRAW)
    draw_header(DRAW, "ARP DIFF", color=C["STEEL"])
    draw_centered(DRAW, "SCAN 2...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    snap2 = {h[0]: h[1] for h in do_scan_hw(network)}

    new_hosts     = [ip for ip in snap2 if ip not in snap1]
    gone_hosts    = [ip for ip in snap1 if ip not in snap2]
    changed_macs  = [ip for ip in snap1 if ip in snap2 and snap1[ip] != snap2[ip]]

    log(f"ARP_DIFF new={len(new_hosts)} gone={len(gone_hosts)} changed={len(changed_macs)}")

    lines = [
        f"NEW: {len(new_hosts)}",
        f"GONE: {len(gone_hosts)}",
        f"MAC CHG: {len(changed_macs)}",
    ]
    for ip in new_hosts[:2]:
        lines.append(f"+ {ip}")
    for ip in changed_macs[:2]:
        lines.append(f"! {ip}")

    color = C["BLOOD"] if (new_hosts or changed_macs) else C["GOOD"]
    draw_result(DRAW, "ARP DIFF", lines, color=color)
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_rogue_detect(iface, network):
    """Detect new unknown MAC addresses on the network."""
    # Load baseline if it exists
    baseline_file = os.path.join(loot_dir(), "baseline.json")
    known_macs = set()
    if os.path.isfile(baseline_file):
        try:
            with open(baseline_file) as f:
                data = json.load(f)
                known_macs = set(h.get("mac", "") for h in data if h.get("mac"))
        except Exception:
            pass

    clear_buf(DRAW)
    draw_header(DRAW, "ROGUE DETECT", color=C["ORANGE"])
    draw_centered(DRAW, "scanning...", 50, FONT_MENU, fill=C["STEEL"])
    if known_macs:
        draw_centered(DRAW, f"baseline: {len(known_macs)}", 65, FONT_SMALL, fill=C["DIM"])
    push(LCD, IMAGE)

    hosts    = do_scan_hw(network)
    rogues   = []
    for h in hosts:
        mac = h[1]
        if mac and mac not in known_macs:
            rogues.append(h)

    log(f"ROGUE_DETECT scanned={len(hosts)} rogues={len(rogues)}")

    if not rogues:
        draw_result(DRAW, "ROGUE DETECT",
                    ["no unknown MACs", f"scanned: {len(hosts)}"],
                    color=C["GOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, f"ROGUES ({len(rogues)})", color=C["BLOOD"])
        draw_hosts(DRAW, rogues, sel)
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(rogues)
        elif btn == "DOWN":
            sel = (sel + 1) % len(rogues)
        elif btn in ("KEY3", "LEFT"):
            break
        time.sleep(0.05)


def op_baseline_export(network):
    """Snapshot current network hosts as the new baseline."""
    clear_buf(DRAW)
    draw_header(DRAW, "BASELINE", color=C["STEEL"])
    draw_centered(DRAW, "scanning...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    hosts = do_scan_hw(network)

    import datetime
    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out   = os.path.join(loot_dir(), f"baseline_{ts}.json")
    base_curr = os.path.join(loot_dir(), "baseline.json")
    data  = [{"ip": h[0], "mac": h[1], "vendor": h[2], "hostname": h[3]}
             for h in hosts]
    try:
        with open(out, "w") as f:
            json.dump(data, f, indent=2)
        with open(base_curr, "w") as f:
            json.dump(data, f, indent=2)
        log(f"BASELINE_EXPORT hosts={len(hosts)} file={out}")
        draw_result(DRAW, "BASELINE",
                    [f"{len(hosts)} hosts", os.path.basename(out)[:18],
                     "saved as baseline"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"baseline error: {e}")
        draw_result(DRAW, "BASELINE ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "RECON", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    network = get_network_cidr(iface)

    sel    = 0
    last_t = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "RECON", color=C["ASH"])
        draw_menu(DRAW, MENU_ITEMS, sel, item_colors=MENU_COLORS)
        draw_status(DRAW, "OK:RUN  KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(MENU_ITEMS)
        elif btn == "DOWN":
            sel = (sel + 1) % len(MENU_ITEMS)
        elif btn in ("OK", "KEY_PRESS", "RIGHT"):
            choice = MENU_ITEMS[sel]

            if choice == "NET SCAN":
                op_net_scan(iface, network, gw_ip)
            elif choice == "TARGET RECON":
                op_target_recon(network, gw_ip)
            elif choice == "ARP SNAPSHOT":
                op_arp_snapshot(iface, network, gw_ip)
            elif choice == "ARP WATCH":
                op_arp_watch_recon(iface)
            elif choice == "ARP DIFF":
                op_arp_diff(iface, network)
            elif choice == "ROGUE DETECT":
                op_rogue_detect(iface, network)
            elif choice == "BASELINE EXPORT":
                op_baseline_export(network)
            elif choice == "< BACK":
                break

        elif btn == "KEY3":
            break
        time.sleep(0.05)


if __name__ == "__main__":
    install_signal_handlers(cleanup)
    try:
        LCD, IMAGE, DRAW = hw_init()
        main()
    finally:
        cleanup()
