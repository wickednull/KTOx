#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_mitm.py — KTOx MITM Engine (Hardware GUI)
#
# Wraps ktox_mitm.py classes with RaspyJack LCD/GPIO interface:
#   DNS Spoofer · DHCP Spoofer · HTTP Sniffer · SSL Stripper
#   Captive Portal · NBNS Poisoner · Full MITM Suite
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
    scan_and_pick, get_iface_and_gateway, get_network_cidr, resolve_mac,
    install_signal_handlers, make_logger, loot_dir,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL, LCD_W, LCD_H,
)

log = make_logger("mitm")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "DNS SPOOF",
    "DHCP SPOOF",
    "HTTP SNIFFER",
    "SSL STRIPPER",
    "CAPTIVE PORTAL",
    "NBNS POISON",
    "FULL MITM",
    "< BACK",
]
MENU_COLORS = [
    C["BLOOD"], C["BLOOD"], C["EMBER"], C["BLOOD"],
    C["ORANGE"], C["BLOOD"], C["EMBER"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


# ─── Import guard ─────────────────────────────────────────────────────────────
def _try_import_mitm():
    try:
        import ktox_mitm as m
        return m
    except Exception as e:
        log(f"import ktox_mitm failed: {e}")
        return None


# ─── Running screen helper ────────────────────────────────────────────────────
def _show_running(title, subtitle=""):
    clear_buf(DRAW)
    draw_running(DRAW, title, line1=subtitle)
    push(LCD, IMAGE)


def _wait_key3_stop(stop_event, title, subtitle=""):
    """Show running indicator until stop_event set or KEY3 pressed."""
    last_t   = 0.0
    elapsed  = 0
    t_start  = time.time()
    while not stop_event.is_set():
        elapsed = int(time.time() - t_start)
        clear_buf(DRAW)
        draw_running(DRAW, title, line1=subtitle, elapsed=elapsed)
        push(LCD, IMAGE)
        btn, last_t = read_btn(last_t)
        if btn in ("KEY3", "LEFT"):
            stop_event.set()
            break
        time.sleep(0.15)


# ══════════════════════════════════════════════════════════════════════════════
# ── MITM OPERATIONS ───────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def op_dns_spoof(m, iface, gw_ip, target_ip):
    """Start DNSSpoofer with a default wildcard redirect to this machine."""
    import socket
    my_ip = socket.gethostbyname(socket.gethostname()) or "192.168.1.1"

    clear_buf(DRAW)
    draw_header(DRAW, "DNS SPOOF", color=C["BLOOD"])
    draw_centered(DRAW, f"Target: {target_ip}", 25, FONT_SMALL, fill=C["WHITE"])
    draw_centered(DRAW, f"→ {my_ip}", 38, FONT_SMALL, fill=C["YELLOW"])
    draw_status(DRAW, "OK:START KEY3:BACK", color=C["DIM"])
    push(LCD, IMAGE)

    btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
    if btn in ("KEY3", "LEFT"):
        return

    stop = threading.Event()
    m.stop_flag.clear()
    try:
        spoofer = m.DNSSpoofer(iface, my_ip, rules={"*": my_ip})
        t = threading.Thread(target=spoofer.start, daemon=True)
        t.start()
        log(f"DNS_SPOOF_START target={target_ip}")
        _wait_key3_stop(stop, "DNS SPOOF", subtitle=target_ip)
        spoofer.stop()
        t.join(timeout=3)
        log("DNS_SPOOF_STOP")
        draw_result(DRAW, "DNS DONE", [target_ip, "Stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"dns_spoof error: {e}")
        draw_result(DRAW, "DNS ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_dhcp_spoof(m, iface, attacker_ip):
    """Start DHCPSpoofer (rogue DHCP server)."""
    stop = threading.Event()
    m.stop_flag.clear()
    try:
        spoofer = m.DHCPSpoofer(iface, attacker_ip)
        t = threading.Thread(target=spoofer.start, daemon=True)
        t.start()
        log("DHCP_SPOOF_START")
        _wait_key3_stop(stop, "DHCP SPOOF", subtitle=iface)
        spoofer.stop()
        t.join(timeout=3)
        log("DHCP_SPOOF_STOP")
        draw_result(DRAW, "DHCP DONE", ["Rogue server", "Stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"dhcp_spoof error: {e}")
        draw_result(DRAW, "DHCP ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_http_sniffer(m, iface):
    """Start HTTPSniffer — extract credentials from intercepted HTTP."""
    stop = threading.Event()
    m.stop_flag.clear()
    try:
        sniffer = m.HTTPSniffer(iface)
        t = threading.Thread(target=sniffer.start, daemon=True)
        t.start()
        log("HTTP_SNIFF_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "HTTP SNIFF",
                         line1="sniffing HTTP", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        sniffer.stop()
        t.join(timeout=3)
        log("HTTP_SNIFF_STOP")
        draw_result(DRAW, "HTTP DONE", ["creds saved to loot"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"http_sniffer error: {e}")
        draw_result(DRAW, "SNIFF ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_ssl_strip(m, iface):
    """Start SSLStripper — downgrade HTTPS to HTTP."""
    stop = threading.Event()
    m.stop_flag.clear()
    try:
        stripper = m.SSLStripper(iface)
        t = threading.Thread(target=stripper.start, daemon=True)
        t.start()
        log("SSL_STRIP_START")
        _wait_key3_stop(stop, "SSL STRIP", subtitle="HTTPS→HTTP")
        stripper.stop()
        t.join(timeout=3)
        log("SSL_STRIP_STOP")
        draw_result(DRAW, "SSL DONE", ["Stripper stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"ssl_strip error: {e}")
        draw_result(DRAW, "SSL ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_captive_portal(m, iface, attacker_ip):
    """Launch captive portal — theme selection then start."""
    themes = ["wifi", "hotel", "corporate", "coffee", "isp"]
    sel    = 0
    last_t = 0.0

    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "CAPTIVE", color=C["ORANGE"])
        draw_menu(DRAW, themes + ["< BACK"], sel,
                  item_colors=[C["ORANGE"]] * len(themes) + [C["DIM"]])
        draw_status(DRAW, "OK:SELECT KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % (len(themes) + 1)
        elif btn == "DOWN":
            sel = (sel + 1) % (len(themes) + 1)
        elif btn in ("OK", "KEY_PRESS"):
            if sel == len(themes):
                return
            theme = themes[sel]
            break
        elif btn in ("KEY3", "LEFT"):
            return
        time.sleep(0.05)

    stop = threading.Event()
    m.stop_flag.clear()
    try:
        portal = m.CaptivePortal(attacker_ip, theme=theme)
        t = threading.Thread(target=portal.start, daemon=True)
        t.start()
        log(f"CAPTIVE_START theme={theme}")
        _wait_key3_stop(stop, "CAPTIVE", subtitle=theme.upper())
        portal.stop()
        t.join(timeout=3)
        log("CAPTIVE_STOP")
        draw_result(DRAW, "PORTAL DONE", [f"Theme: {theme}", "Stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"captive error: {e}")
        draw_result(DRAW, "PORTAL ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_nbns_poison(m, iface, attacker_ip):
    """Start NBNS/mDNS poisoner."""
    stop = threading.Event()
    m.stop_flag.clear()
    try:
        poisoner = m.NBNSPoisoner(iface, attacker_ip)
        t = threading.Thread(target=poisoner.start, daemon=True)
        t.start()
        log("NBNS_START")
        _wait_key3_stop(stop, "NBNS", subtitle="UDP/137")
        poisoner.stop()
        t.join(timeout=3)
        log("NBNS_STOP")
        draw_result(DRAW, "NBNS DONE", ["Poisoner stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"nbns error: {e}")
        draw_result(DRAW, "NBNS ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_full_mitm(m, iface, attacker_ip, gw_ip):
    """Launch full MITM suite via ktox_mitm.launch_full_mitm()."""
    stop = threading.Event()
    try:
        t = threading.Thread(
            target=m.launch_full_mitm,
            kwargs={"iface": iface, "attacker_ip": attacker_ip, "gateway_ip": gw_ip},
            daemon=True,
        )
        t.start()
        log("FULL_MITM_START")
        _wait_key3_stop(stop, "FULL MITM", subtitle=gw_ip or "")
        # Signal stop — launch_full_mitm respects a global stop event
        if hasattr(m, "_mitm_stop"):
            m._mitm_stop.set()
        t.join(timeout=5)
        log("FULL_MITM_STOP")
        draw_result(DRAW, "MITM DONE", ["All modules", "stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"full_mitm error: {e}")
        draw_result(DRAW, "MITM ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    m = _try_import_mitm()
    if not m:
        clear_buf(DRAW)
        draw_header(DRAW, "MITM", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_mitm missing", 50, FONT_MENU, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "MITM", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    import socket
    try:
        attacker_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        attacker_ip = "127.0.0.1"

    network = get_network_cidr(iface)
    sel     = 0
    last_t  = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "MITM ENGINE", color=C["EMBER"])
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

            if choice == "DNS SPOOF":
                host = scan_and_pick(LCD, IMAGE, DRAW, iface, network,
                                     title="DNS TARGET", allow_gw=False, gateway_ip=gw_ip)
                if host:
                    op_dns_spoof(m, iface, gw_ip, host[0])

            elif choice == "DHCP SPOOF":
                op_dhcp_spoof(m, iface, attacker_ip)

            elif choice == "HTTP SNIFFER":
                op_http_sniffer(m, iface)

            elif choice == "SSL STRIPPER":
                op_ssl_strip(m, iface)

            elif choice == "CAPTIVE PORTAL":
                op_captive_portal(m, iface, attacker_ip)

            elif choice == "NBNS POISON":
                op_nbns_poison(m, iface, attacker_ip)

            elif choice == "FULL MITM":
                op_full_mitm(m, iface, attacker_ip, gw_ip)

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
