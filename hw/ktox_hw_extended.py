#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_extended.py — KTOx Extended Engine (Hardware GUI)
#
# Wraps ktox_extended.py with RaspyJack LCD/GPIO interface:
#   LLMNR Poisoner · NBT-NS Poisoner · WPAD Poisoner
#   Rogue SMB Server · Hash Cracker · Topology Mapper · Report Generator
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

log = make_logger("extended")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "LLMNR POISON",
    "NBT-NS POISON",
    "WPAD POISON",
    "ROGUE SMB",
    "HASH CRACKER",
    "TOPO MAP",
    "GEN REPORT",
    "< BACK",
]
MENU_COLORS = [
    C["BLOOD"], C["BLOOD"], C["BLOOD"], C["EMBER"],
    C["ORANGE"], C["STEEL"], C["STEEL"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


def _try_import_ext():
    try:
        import ktox_extended as x
        return x
    except Exception as e:
        log(f"import ktox_extended failed: {e}")
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

def op_llmnr(x, iface, attacker_ip):
    stop  = threading.Event()
    pkts  = [0]
    hashes = []
    try:
        poisoner = x.LLMNRPoisoner(
            iface=iface, attacker_ip=attacker_ip,
            loot_callback=lambda h: hashes.append(h),
        )
        t = threading.Thread(target=poisoner.start, daemon=True)
        t.start()
        log("LLMNR_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "LLMNR",
                         line1=f"{len(hashes)} hashes", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        poisoner.stop()
        t.join(timeout=3)
        log(f"LLMNR_STOP hashes={len(hashes)}")
        draw_result(DRAW, "LLMNR DONE",
                    [f"{len(hashes)} NTLMv2", "hashes captured"], color=C["GOOD"])
    except Exception as e:
        log(f"llmnr error: {e}")
        draw_result(DRAW, "LLMNR ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_nbtns(x, iface, attacker_ip):
    stop  = threading.Event()
    hashes = []
    try:
        # NBT-NS uses same LLMNRPoisoner pattern with nbt mode in ktox_extended
        poisoner = x.NBNSPoisoner(
            iface=iface, attacker_ip=attacker_ip,
            loot_callback=lambda h: hashes.append(h),
        ) if hasattr(x, "NBNSPoisoner") else x.LLMNRPoisoner(
            iface=iface, attacker_ip=attacker_ip, proto="nbtns",
            loot_callback=lambda h: hashes.append(h),
        )
        t = threading.Thread(target=poisoner.start, daemon=True)
        t.start()
        log("NBTNS_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "NBT-NS",
                         line1=f"{len(hashes)} hashes", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        poisoner.stop()
        t.join(timeout=3)
        log(f"NBTNS_STOP hashes={len(hashes)}")
        draw_result(DRAW, "NBT-NS DONE",
                    [f"{len(hashes)} hashes"], color=C["GOOD"])
    except Exception as e:
        log(f"nbtns error: {e}")
        draw_result(DRAW, "NBTNS ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_wpad(x, iface, attacker_ip):
    stop  = threading.Event()
    hashes = []
    try:
        poisoner = x.WPADPoisoner(
            iface=iface, attacker_ip=attacker_ip,
            loot_callback=lambda h: hashes.append(h),
        )
        t = threading.Thread(target=poisoner.start, daemon=True)
        t.start()
        log("WPAD_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "WPAD",
                         line1=f"{len(hashes)} creds", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        poisoner.stop()
        t.join(timeout=3)
        log(f"WPAD_STOP hashes={len(hashes)}")
        draw_result(DRAW, "WPAD DONE",
                    [f"{len(hashes)} creds"], color=C["GOOD"])
    except Exception as e:
        log(f"wpad error: {e}")
        draw_result(DRAW, "WPAD ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_rogue_smb(x, iface, attacker_ip):
    stop  = threading.Event()
    hashes = []
    try:
        server = x.RogueSMBServer(
            iface=iface, attacker_ip=attacker_ip,
            loot_callback=lambda h: hashes.append(h),
        )
        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        log("ROGUE_SMB_START")

        last_t  = 0.0
        elapsed = 0
        t_start = time.time()
        while not stop.is_set():
            elapsed = int(time.time() - t_start)
            clear_buf(DRAW)
            draw_running(DRAW, "ROGUE SMB",
                         line1=f"{len(hashes)} NTLMv2", elapsed=elapsed)
            push(LCD, IMAGE)
            btn, last_t = read_btn(last_t)
            if btn in ("KEY3", "LEFT"):
                stop.set()
            time.sleep(0.15)

        server.stop()
        t.join(timeout=3)
        log(f"ROGUE_SMB_STOP hashes={len(hashes)}")
        draw_result(DRAW, "SMB DONE",
                    [f"{len(hashes)} NTLMv2", "saved to loot"], color=C["GOOD"])
    except Exception as e:
        log(f"rogue_smb error: {e}")
        draw_result(DRAW, "SMB ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_hash_crack(x):
    """Hash cracker — tries hashcat then john on captured NTLMv2 hashes."""
    hash_file = os.path.join(loot_dir(), "ntlm_hashes.txt")
    if not os.path.isfile(hash_file):
        clear_buf(DRAW)
        draw_header(DRAW, "HASH CRACK", color=C["ORANGE"])
        draw_centered(DRAW, "no hashes found", 45, FONT_MENU, fill=C["STEEL"])
        draw_centered(DRAW, "run LLMNR/SMB first", 60, FONT_SMALL, fill=C["DIM"])
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    # Count hashes
    try:
        with open(hash_file) as f:
            n_hashes = sum(1 for l in f if l.strip())
    except Exception:
        n_hashes = 0

    clear_buf(DRAW)
    draw_header(DRAW, "HASH CRACK", color=C["ORANGE"])
    draw_centered(DRAW, f"{n_hashes} hashes", 30, FONT_MENU, fill=C["WHITE"])
    draw_centered(DRAW, "wordlist: rockyou", 46, FONT_SMALL, fill=C["STEEL"])
    draw_status(DRAW, "OK:START KEY3:BACK", color=C["DIM"])
    push(LCD, IMAGE)

    btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
    if btn in ("KEY3", "LEFT"):
        return

    stop = threading.Event()
    try:
        cracker = x.HashCracker(hash_file=hash_file)
        t = threading.Thread(target=cracker.run, daemon=True)
        t.start()
        log("HASH_CRACK_START")
        _wait_stop(stop, "CRACKING", subtitle="hashcat/john")
        cracker.stop()
        t.join(timeout=5)
        results = cracker.get_results() if hasattr(cracker, "get_results") else []
        log(f"HASH_CRACK_STOP found={len(results)}")
        draw_result(DRAW, "CRACK DONE",
                    [f"{len(results)} cracked", "saved to loot"], color=C["GOOD"])
    except Exception as e:
        log(f"hash_crack error: {e}")
        draw_result(DRAW, "CRACK ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_topo_map(x):
    """Generate HTML network topology map from scan data."""
    clear_buf(DRAW)
    draw_header(DRAW, "TOPO MAP", color=C["STEEL"])
    draw_centered(DRAW, "building map...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        mapper = x.TopologyMapper(loot_directory=loot_dir())
        out    = mapper.generate()
        log(f"TOPO_MAP out={out}")
        draw_result(DRAW, "TOPO DONE",
                    [os.path.basename(str(out))[:18], "saved to loot"], color=C["GOOD"])
    except Exception as e:
        log(f"topo_map error: {e}")
        draw_result(DRAW, "TOPO ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_report(x):
    """Generate Markdown + HTML pentest report."""
    clear_buf(DRAW)
    draw_header(DRAW, "REPORT", color=C["STEEL"])
    draw_centered(DRAW, "generating...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        gen = x.ReportGenerator(loot_directory=loot_dir())
        out = gen.generate()
        log(f"REPORT out={out}")
        draw_result(DRAW, "REPORT DONE",
                    [os.path.basename(str(out))[:18], "saved to loot"], color=C["GOOD"])
    except Exception as e:
        log(f"report error: {e}")
        draw_result(DRAW, "REPORT ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    x = _try_import_ext()
    if not x:
        clear_buf(DRAW)
        draw_header(DRAW, "EXTENDED", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_extended", 40, FONT_MENU, fill=C["ORANGE"])
        draw_centered(DRAW, "not found", 55, FONT_SMALL, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "EXTENDED", color=C["BLOOD"])
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
        draw_header(DRAW, "EXTENDED", color=C["ORANGE"])
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

            if choice == "LLMNR POISON":
                op_llmnr(x, iface, attacker_ip)
            elif choice == "NBT-NS POISON":
                op_nbtns(x, iface, attacker_ip)
            elif choice == "WPAD POISON":
                op_wpad(x, iface, attacker_ip)
            elif choice == "ROGUE SMB":
                op_rogue_smb(x, iface, attacker_ip)
            elif choice == "HASH CRACKER":
                op_hash_crack(x)
            elif choice == "TOPO MAP":
                op_topo_map(x)
            elif choice == "GEN REPORT":
                op_report(x)
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
