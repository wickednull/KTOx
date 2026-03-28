#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_stealth.py — KTOx Stealth + IoT Fingerprint Engine (Hardware GUI)
#
# Wraps ktox_stealth.py with RaspyJack LCD/GPIO interface:
#   IoT Fingerprinter (5-layer) · Stealth Mode (Ghost/Ninja/Normal/Custom)
#   MAC Rotation Status · Rate Limit Control
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

log = make_logger("stealth")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "FINGERPRINT",
    "STEALTH: GHOST",
    "STEALTH: NINJA",
    "STEALTH: NORMAL",
    "STEALTH: CUSTOM",
    "< BACK",
]
MENU_COLORS = [
    C["ASH"], C["DIM"], C["STEEL"], C["ASH"], C["ORANGE"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


def _try_import_stealth():
    try:
        import ktox_stealth as s
        return s
    except Exception as e:
        log(f"import ktox_stealth failed: {e}")
        return None


def _wait_stop(stop_event, title, subtitle=""):
    last_t  = 0.0
    elapsed = 0
    t_start = time.time()
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

def op_fingerprint(s, iface, network, gw_ip):
    """5-layer IoT device fingerprinting on a chosen host or all hosts."""
    options = ["FINGERPRINT ONE", "FINGERPRINT ALL", "< BACK"]
    sel     = 0
    last_t  = 0.0

    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "FINGERPRINT", color=C["ASH"])
        draw_menu(DRAW, options, sel,
                  item_colors=[C["WHITE"], C["WHITE"], C["DIM"]])
        draw_status(DRAW, "OK:SELECT KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(options)
        elif btn == "DOWN":
            sel = (sel + 1) % len(options)
        elif btn in ("OK", "KEY_PRESS"):
            if options[sel] == "< BACK":
                return
            mode = options[sel]
            break
        elif btn in ("KEY3", "LEFT"):
            return
        time.sleep(0.05)

    targets = []
    if mode == "FINGERPRINT ONE":
        host = scan_and_pick(LCD, IMAGE, DRAW, iface, network,
                             title="FP TARGET", allow_gw=True)
        if host:
            targets = [host[0]]
    else:
        clear_buf(DRAW)
        draw_header(DRAW, "FINGERPRINT", color=C["ASH"])
        draw_centered(DRAW, "scanning all...", 50, FONT_MENU, fill=C["STEEL"])
        push(LCD, IMAGE)
        from ktox_hw_utils import do_scan_hw
        hosts = do_scan_hw(network)
        targets = [h[0] for h in hosts]

    if not targets:
        return

    results = []
    clear_buf(DRAW)
    draw_header(DRAW, "FP SCAN", color=C["ASH"])
    draw_centered(DRAW, f"0/{len(targets)} done", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        fp = s.IoTFingerprinter(iface=iface)
        for i, target_ip in enumerate(targets):
            clear_buf(DRAW)
            draw_header(DRAW, "FP SCAN", color=C["ASH"])
            draw_centered(DRAW, f"{i+1}/{len(targets)}", 35, FONT_MENU, fill=C["STEEL"])
            draw_centered(DRAW, target_ip, 52, FONT_SMALL, fill=C["WHITE"])
            push(LCD, IMAGE)

            result = fp.fingerprint(target_ip)
            results.append(result)
            log(f"FP_RESULT ip={target_ip} type={result.get('device_type','?')}")

    except Exception as e:
        log(f"fingerprint error: {e}")
        draw_result(DRAW, "FP ERR", [str(e)[:20]], color=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    # Show results scrollable
    if not results:
        draw_result(DRAW, "FP DONE", ["no results"], color=C["ORANGE"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, f"FP ({len(results)})", color=C["ASH"])
        labels = []
        for r in results:
            ip    = r.get("ip", "?")
            dtype = r.get("device_type", "unknown")[:10]
            conf  = r.get("confidence", 0)
            labels.append(f"{ip[:12]} {dtype} {conf}%")
        draw_menu(DRAW, labels, sel, item_colors=[C["WHITE"]] * len(results))
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(results)
        elif btn == "DOWN":
            sel = (sel + 1) % len(results)
        elif btn in ("OK", "KEY_PRESS"):
            # Show detail for selected result
            r = results[sel]
            detail_lines = [
                f"IP: {r.get('ip','?')}",
                f"Type: {r.get('device_type','?')[:16]}",
                f"Conf: {r.get('confidence',0)}%",
                f"Vendor: {r.get('vendor','?')[:14]}",
                f"OS: {r.get('os','?')[:16]}",
            ]
            draw_result(DRAW, "FP DETAIL", detail_lines, color=C["ASH"])
            push(LCD, IMAGE)
            wait_for_btn(["KEY3", "LEFT", "OK"])
        elif btn in ("KEY3", "LEFT"):
            break
        time.sleep(0.05)


def op_stealth(s, iface, profile_name, custom=False):
    """Activate a stealth profile for rate limiting + MAC rotation."""
    if custom:
        clear_buf(DRAW)
        draw_header(DRAW, "CUSTOM", color=C["ORANGE"])
        draw_centered(DRAW, "ppm:  60",   30, FONT_MENU, fill=C["WHITE"])
        draw_centered(DRAW, "jitter: 1s", 46, FONT_MENU, fill=C["WHITE"])
        draw_centered(DRAW, "MAC: off",   62, FONT_MENU, fill=C["WHITE"])
        draw_status(DRAW, "OK:START KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)
        btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
        if btn in ("KEY3", "LEFT"):
            return

    # Map display name to profile key (StealthMode uses lowercase keys)
    profile_key = profile_name.lower()  # "GHOST"→"ghost", "NINJA"→"ninja" etc.

    stop = threading.Event()
    try:
        mode = s.StealthMode(iface, profile=profile_key)
        mode.start()  # non-blocking — launches background threads
        log(f"STEALTH_START profile={profile_key}")
        _wait_stop(stop, "STEALTH", subtitle=profile_name)
        mode.stop()
        log(f"STEALTH_STOP profile={profile_key}")
        draw_result(DRAW, "STEALTH OFF",
                    [f"Profile: {profile_name}", "MAC restored"], color=C["GOOD"])
    except Exception as e:
        log(f"stealth error: {e}")
        draw_result(DRAW, "STEALTH ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    s = _try_import_stealth()
    if not s:
        clear_buf(DRAW)
        draw_header(DRAW, "STEALTH", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_stealth", 40, FONT_MENU, fill=C["ORANGE"])
        draw_centered(DRAW, "not found", 55, FONT_SMALL, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "STEALTH", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    network = get_network_cidr(iface)
    sel     = 0
    last_t  = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "STEALTH", color=C["STEEL"])
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

            if choice == "FINGERPRINT":
                op_fingerprint(s, iface, network, gw_ip)
            elif choice == "STEALTH: GHOST":
                op_stealth(s, iface, "GHOST")
            elif choice == "STEALTH: NINJA":
                op_stealth(s, iface, "NINJA")
            elif choice == "STEALTH: NORMAL":
                op_stealth(s, iface, "NORMAL")
            elif choice == "STEALTH: CUSTOM":
                op_stealth(s, iface, "CUSTOM", custom=True)
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
