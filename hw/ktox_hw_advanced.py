#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_advanced.py — KTOx Advanced Engine (Hardware GUI)
#
# Wraps ktox_advanced.py with RaspyJack LCD/GPIO interface:
#   JS Injector · Multi-Protocol Sniffer · PCAP Capture
#   NTLMv2 Capture · Session Hijacker · Caplet Runner
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
    get_iface_and_gateway, get_network_cidr,
    install_signal_handlers, make_logger, loot_dir,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL, LCD_W, LCD_H,
)

log = make_logger("advanced")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "JS INJECT",
    "PROTO SNIFF",
    "PCAP CAPTURE",
    "NTLM CAPTURE",
    "SESSION HIJACK",
    "CAPLET RUNNER",
    "< BACK",
]
MENU_COLORS = [
    C["BLOOD"], C["EMBER"], C["STEEL"],
    C["BLOOD"], C["EMBER"], C["ORANGE"], C["DIM"],
]

JS_PAYLOADS = [
    "keylogger",
    "credential_intercept",
    "session_stealer",
    "beef_hook",
    "redirect",
    "camera_grab",
    "alert_test",
    "crypto_miner",
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


def _try_import_adv():
    try:
        import ktox_advanced as a
        return a
    except Exception as e:
        log(f"import ktox_advanced failed: {e}")
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
# ── OPERATIONS ────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def op_js_inject(a, iface, attacker_ip):
    """Pick JS payload type then start JSInjector."""
    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "JS PAYLOAD", color=C["BLOOD"])
        draw_menu(DRAW, JS_PAYLOADS + ["< BACK"], sel,
                  item_colors=[C["BLOOD"]] * len(JS_PAYLOADS) + [C["DIM"]])
        draw_status(DRAW, "OK:SELECT KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % (len(JS_PAYLOADS) + 1)
        elif btn == "DOWN":
            sel = (sel + 1) % (len(JS_PAYLOADS) + 1)
        elif btn in ("OK", "KEY_PRESS"):
            if sel == len(JS_PAYLOADS):
                return
            payload = JS_PAYLOADS[sel]
            break
        elif btn in ("KEY3", "LEFT"):
            return
        time.sleep(0.05)

    stop = threading.Event()
    pkts = [0]
    try:
        injector = a.JSInjector(iface=iface, payload_type=payload,
                                attacker_ip=attacker_ip)
        t = threading.Thread(target=injector.start, daemon=True)
        t.start()
        log(f"JS_INJECT_START payload={payload}")
        _wait_stop(stop, "JS INJECT", subtitle=payload, pkt_ref=pkts)
        injector.stop()
        t.join(timeout=3)
        log("JS_INJECT_STOP")
        draw_result(DRAW, "JS DONE", [f"Payload: {payload}", "Stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"js_inject error: {e}")
        draw_result(DRAW, "JS ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_proto_sniff(a, iface):
    """Multi-protocol credential sniffer."""
    stop  = threading.Event()
    pkts  = [0]
    creds = []

    try:
        sniffer = a.MultiProtocolSniffer(
            iface=iface,
            loot_callback=lambda c: creds.append(c),
        )
        t = threading.Thread(target=sniffer.start, daemon=True)
        t.start()
        log("PROTO_SNIFF_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "PROTO SNIFF",
                         line1=f"{len(creds)} creds", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        sniffer.stop()
        t.join(timeout=3)
        log(f"PROTO_SNIFF_STOP creds={len(creds)}")
        draw_result(DRAW, "SNIFF DONE",
                    [f"{len(creds)} creds captured", "saved to loot"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"proto_sniff error: {e}")
        draw_result(DRAW, "SNIFF ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_pcap(a, iface):
    """Wireshark-compatible PCAP capture."""
    import datetime
    outfile = os.path.join(loot_dir(),
                           f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
    stop  = threading.Event()
    pkts  = [0]
    try:
        capture = a.PCAPCapture(iface=iface, output_file=outfile)
        t = threading.Thread(target=capture.start, daemon=True)
        t.start()
        log(f"PCAP_START file={outfile}")
        _wait_stop(stop, "PCAP", subtitle=os.path.basename(outfile), pkt_ref=pkts)
        capture.stop()
        t.join(timeout=3)
        size_kb = os.path.getsize(outfile) // 1024 if os.path.isfile(outfile) else 0
        log(f"PCAP_STOP size={size_kb}KB")
        draw_result(DRAW, "PCAP DONE",
                    [f"{size_kb} KB", os.path.basename(outfile)[:18]],
                    color=C["GOOD"])
    except Exception as e:
        log(f"pcap error: {e}")
        draw_result(DRAW, "PCAP ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_ntlm(a, iface):
    """NTLMv2 hash capture from HTTP + SMB traffic."""
    stop  = threading.Event()
    hashes = []
    try:
        capture = a.NTLMCapture(
            iface=iface,
            loot_callback=lambda h: hashes.append(h),
        )
        t = threading.Thread(target=capture.start, daemon=True)
        t.start()
        log("NTLM_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "NTLM CAPTURE",
                         line1=f"{len(hashes)} hashes", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        capture.stop()
        t.join(timeout=3)
        log(f"NTLM_STOP hashes={len(hashes)}")
        draw_result(DRAW, "NTLM DONE",
                    [f"{len(hashes)} hashes", "saved to loot"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"ntlm error: {e}")
        draw_result(DRAW, "NTLM ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_session_hijack(a, iface):
    """Cookie theft + curl replay script generation."""
    stop    = threading.Event()
    sessions = []
    try:
        hijacker = a.SessionHijacker(
            iface=iface,
            loot_callback=lambda s: sessions.append(s),
        )
        t = threading.Thread(target=hijacker.start, daemon=True)
        t.start()
        log("SESSION_HIJACK_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "SESS HIJACK",
                         line1=f"{len(sessions)} cookies", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        hijacker.stop()
        t.join(timeout=3)
        log(f"SESSION_HIJACK_STOP sessions={len(sessions)}")
        draw_result(DRAW, "HIJACK DONE",
                    [f"{len(sessions)} cookies", "curl scripts saved"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"session_hijack error: {e}")
        draw_result(DRAW, "HIJACK ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_caplet(a, iface, attacker_ip, gw_ip):
    """Caplet automation engine — lists available .ktox scripts."""
    caplet_dir = os.path.join(_ROOT, "caplets")
    caplets    = []
    if os.path.isdir(caplet_dir):
        caplets = [f for f in os.listdir(caplet_dir) if f.endswith(".ktox")]

    if not caplets:
        clear_buf(DRAW)
        draw_header(DRAW, "CAPLETS", color=C["ORANGE"])
        draw_centered(DRAW, "No .ktox scripts", 40, FONT_MENU, fill=C["STEEL"])
        draw_centered(DRAW, f"put in:", 55, FONT_SMALL, fill=C["DIM"])
        draw_centered(DRAW, "caplets/", 66, FONT_SMALL, fill=C["ASH"])
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "CAPLETS", color=C["ORANGE"])
        draw_menu(DRAW, caplets + ["< BACK"], sel,
                  item_colors=[C["ORANGE"]] * len(caplets) + [C["DIM"]])
        draw_status(DRAW, "OK:RUN KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % (len(caplets) + 1)
        elif btn == "DOWN":
            sel = (sel + 1) % (len(caplets) + 1)
        elif btn in ("OK", "KEY_PRESS"):
            if sel == len(caplets):
                return
            caplet_path = os.path.join(caplet_dir, caplets[sel])
            break
        elif btn in ("KEY3", "LEFT"):
            return
        time.sleep(0.05)

    stop = threading.Event()
    try:
        engine = a.CapletEngine(
            iface=iface, attacker_ip=attacker_ip, gateway_ip=gw_ip
        )
        t = threading.Thread(
            target=engine.run_file, args=(caplet_path,), daemon=True
        )
        t.start()
        log(f"CAPLET_START file={caplets[sel]}")
        _wait_stop(stop, "CAPLET", subtitle=caplets[sel][:16])
        engine.stop()
        t.join(timeout=5)
        log("CAPLET_STOP")
        draw_result(DRAW, "CAPLET DONE", [caplets[sel][:18], "Complete"], color=C["GOOD"])
    except Exception as e:
        log(f"caplet error: {e}")
        draw_result(DRAW, "CAPLET ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    a = _try_import_adv()
    if not a:
        clear_buf(DRAW)
        draw_header(DRAW, "ADVANCED", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_advanced", 40, FONT_MENU, fill=C["ORANGE"])
        draw_centered(DRAW, "not found", 55, FONT_SMALL, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "ADVANCED", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    import socket
    try:
        attacker_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        attacker_ip = "127.0.0.1"

    sel    = 0
    last_t = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "ADVANCED", color=C["BLOOD"])
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

            if choice == "JS INJECT":
                op_js_inject(a, iface, attacker_ip)
            elif choice == "PROTO SNIFF":
                op_proto_sniff(a, iface)
            elif choice == "PCAP CAPTURE":
                op_pcap(a, iface)
            elif choice == "NTLM CAPTURE":
                op_ntlm(a, iface)
            elif choice == "SESSION HIJACK":
                op_session_hijack(a, iface)
            elif choice == "CAPLET RUNNER":
                op_caplet(a, iface, attacker_ip, gw_ip)
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
