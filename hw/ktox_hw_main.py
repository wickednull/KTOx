#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_main.py — KTOx RaspyJack Top-Level Menu
#
# Entry-point payload for the KTOx suite on RaspyJack hardware.
# Shows category selection on the 128×128 LCD; each category launches
# its own sub-menu script as a subprocess (full process isolation per
# RaspyJack payload pattern).
#
# Controls:
#   UP / DOWN  — scroll categories
#   OK         — launch selected category
#   KEY3       — exit to RaspyJack main menu

import sys
import os
import time
import signal
import subprocess

# Resolve paths relative to this file
_HW_DIR   = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_HW_DIR)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from ktox_hw_utils import (
    hw_init, hw_cleanup, push,
    clear_buf, draw_header, draw_status, draw_menu, draw_centered,
    read_btn, wait_for_btn,
    install_signal_handlers,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL,
    LCD_W, LCD_H,
)

# ─── Globals ──────────────────────────────────────────────────────────────────
LCD    = None
IMAGE  = None
DRAW   = None
RUNNING = True

# ─── Category registry ────────────────────────────────────────────────────────
#   (label, script_filename, label_color)
CATEGORIES = [
    ("[ ATTACK ]",    "ktox_hw_attack.py",    C["BLOOD"]),
    ("[ MITM ]",      "ktox_hw_mitm.py",      C["EMBER"]),
    ("[ ADVANCED ]",  "ktox_hw_advanced.py",  C["BLOOD"]),
    ("[ EXTENDED ]",  "ktox_hw_extended.py",  C["ORANGE"]),
    ("[ WIFI ]",      "ktox_hw_wifi.py",      C["ORANGE"]),
    ("[ NETATTACK ]", "ktox_hw_netattack.py", C["BLOOD"]),
    ("[ STEALTH ]",   "ktox_hw_stealth.py",   C["STEEL"]),
    ("[ RECON ]",     "ktox_hw_recon.py",     C["ASH"]),
    ("[ DEFENSE ]",   "ktox_hw_defense.py",   C["GOOD"]),
]
LABELS  = [c[0] for c in CATEGORIES]
SCRIPTS = [c[1] for c in CATEGORIES]
COLORS  = [c[2] for c in CATEGORIES]


# ─── Cleanup ──────────────────────────────────────────────────────────────────
def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


# ─── Splash screen ────────────────────────────────────────────────────────────
def draw_splash():
    clear_buf(DRAW)
    # Blood-red banner block
    DRAW.rectangle([(0, 0), (LCD_W, 40)], fill=C["BGHDR"])
    DRAW.line([(0, 40), (LCD_W, 40)], fill=C["BLOOD"], width=2)
    draw_centered(DRAW, "KTOx",     8,  FONT_TITLE, fill=C["BLOOD"])
    draw_centered(DRAW, "v10.0",    22, FONT_SMALL, fill=C["RUST"])
    draw_centered(DRAW, "Purple Team Suite", 33, FONT_SMALL, fill=C["STEEL"])
    draw_centered(DRAW, "by wickednull",      48, FONT_SMALL, fill=C["DIM"])
    draw_centered(DRAW, "authorized eyes only", 62, FONT_SMALL, fill=C["DIM"])
    draw_status(DRAW, "OK: ENTER MENU", color=C["BLOOD"])
    push(LCD, IMAGE)


# ─── Main menu draw ───────────────────────────────────────────────────────────
def draw_main_menu(sel):
    clear_buf(DRAW)
    draw_header(DRAW, "KTOx SUITE", color=C["BLOOD"])
    draw_menu(DRAW, LABELS, sel, item_colors=COLORS)
    draw_status(DRAW, "OK:SELECT KEY3:EXIT", color=C["DIM"])
    push(LCD, IMAGE)


# ─── Launch sub-menu script ───────────────────────────────────────────────────
def launch_script(script_name):
    """Fork the selected category script as a child process."""
    path = os.path.join(_HW_DIR, script_name)
    if not os.path.isfile(path):
        clear_buf(DRAW)
        draw_header(DRAW, "ERROR", color=C["BLOOD"])
        draw_centered(DRAW, "Script missing:", 35, FONT_SMALL, fill=C["ORANGE"])
        draw_centered(DRAW, script_name[:20], 48, FONT_SMALL, fill=C["ASH"])
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    try:
        subprocess.run([sys.executable, path], check=False)
    except Exception as e:
        clear_buf(DRAW)
        draw_header(DRAW, "LAUNCH ERR", color=C["BLOOD"])
        draw_centered(DRAW, str(e)[:20], 45, FONT_SMALL, fill=C["ORANGE"])
        draw_status(DRAW, "KEY3: BACK", color=C["DIM"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])

    # Re-init LCD after child exits (child calls GPIO.cleanup())
    global LCD, IMAGE, DRAW
    LCD, IMAGE, DRAW = hw_init()


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    install_signal_handlers(cleanup)

    try:
        LCD, IMAGE, DRAW = hw_init()

        # Splash
        draw_splash()
        wait_for_btn(["OK", "KEY_PRESS", "RIGHT"], timeout=4)

        sel   = 0
        last_t = 0.0

        while RUNNING:
            draw_main_menu(sel)

            btn, last_t = read_btn(last_t)
            if btn == "UP":
                sel = (sel - 1) % len(CATEGORIES)
            elif btn == "DOWN":
                sel = (sel + 1) % len(CATEGORIES)
            elif btn in ("OK", "KEY_PRESS", "RIGHT"):
                launch_script(SCRIPTS[sel])
            elif btn == "KEY3":
                break
            time.sleep(0.05)

    finally:
        cleanup()
