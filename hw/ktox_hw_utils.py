#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_utils.py — KTOx RaspyJack Hardware Utilities
#
# Shared LCD + GPIO helpers for all KTOx hardware GUI scripts.
# Follows the RaspyJack payload pattern:
#   · Process-isolated (import in each payload script)
#   · GPIO.cleanup() in every finally block
#   · Draws to PIL buffer first, then pushes to LCD
#   · Debounced button reads
#   · KTOx colour palette (dark / blood-red)

import os
import sys
import time
import signal
import threading
import subprocess

# ─── GPIO / LCD (graceful fallback for non-Pi dev environments) ────────────────
try:
    import RPi.GPIO as GPIO
    from PIL import Image, ImageDraw, ImageFont
    import LCD_Config          # noqa: F401  — must import to init SPI
    import LCD_1in44
    _HW_AVAILABLE = True
except ImportError:
    _HW_AVAILABLE = False
    # Stub so the rest of the code doesn't explode on import
    class _StubGPIO:
        BCM = PUD_UP = IN = OUT = 0
        def setmode(self, *a): pass
        def setup(self, *a, **k): pass
        def input(self, *a): return 1
        def cleanup(self): pass
    GPIO = _StubGPIO()

# ─── Waveshare 1.44-inch LCD HAT pin layout ────────────────────────────────────
PINS = {
    "UP":    6,
    "DOWN":  19,
    "LEFT":  5,
    "RIGHT": 26,
    "OK":    13,   # centre joystick press / select
    "KEY1":  21,
    "KEY2":  20,
    "KEY3":  16,   # universal exit / panic
}

# ─── Screen dimensions ─────────────────────────────────────────────────────────
LCD_W = 128
LCD_H = 128

# ─── KTOx colour palette (maps to the TUI palette in ktox.py) ──────────────────
C = {
    "BLACK":   "#000000",
    "WHITE":   "#F2F3F4",   # C_WHITE
    "BLOOD":   "#C0392B",   # C_BLOOD  — primary red
    "RUST":    "#922B21",   # C_RUST   — dark red / header bg
    "EMBER":   "#E74C3C",   # C_EMBER  — bright red accent
    "ASH":     "#ABB2B9",   # C_ASH
    "STEEL":   "#717D7E",   # C_STEEL
    "DIM":     "#566573",   # C_DIM
    "ORANGE":  "#CA6F1E",   # C_ORANGE
    "YELLOW":  "#D4AC0D",   # C_YELLOW
    "GOOD":    "#1E8449",   # C_GOOD   — defense / ok green
    "BGSEL":   "#5B1A1A",   # selected row background (deep blood)
    "BGHDR":   "#1A0000",   # header bar background (near-black red)
    "BGSTATUS":"#0A0A0A",   # status bar background
}

# ─── Font loader ───────────────────────────────────────────────────────────────
_FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

def _load_fonts():
    try:
        from PIL import ImageFont
        return (
            ImageFont.truetype(_FONT_PATH, 11),  # title / header
            ImageFont.truetype(_FONT_PATH, 10),  # menu items
            ImageFont.truetype(_FONT_PATH,  8),  # status / small
        )
    except Exception:
        try:
            from PIL import ImageFont
            d = ImageFont.load_default()
            return d, d, d
        except Exception:
            return None, None, None

FONT_TITLE, FONT_MENU, FONT_SMALL = _load_fonts()


# ══════════════════════════════════════════════════════════════════════════════
# ── HARDWARE INIT / CLEANUP ───────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def hw_init():
    """Initialise GPIO pins and LCD.  Returns (lcd, image, draw)."""
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    if _HW_AVAILABLE:
        from PIL import Image, ImageDraw
        lcd = LCD_1in44.LCD()
        lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        lcd.LCD_Clear()
        image = Image.new("RGB", (LCD_W, LCD_H), C["BLACK"])
        draw  = ImageDraw.Draw(image)
        return lcd, image, draw
    else:
        return None, None, None


def hw_cleanup(lcd=None):
    """Release all hardware — MUST be called in every finally block."""
    try:
        if lcd:
            lcd.LCD_Clear()
    except Exception:
        pass
    try:
        GPIO.cleanup()
    except Exception:
        pass


def push(lcd, image):
    """Push PIL image buffer to physical LCD."""
    if lcd and image:
        lcd.LCD_ShowImage(image, 0, 0)


# ══════════════════════════════════════════════════════════════════════════════
# ── DRAWING HELPERS ───────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def clear_buf(draw):
    """Fill the entire canvas with black."""
    if draw:
        draw.rectangle([(0, 0), (LCD_W, LCD_H)], fill=C["BLACK"])


def draw_centered(draw, text, y, font=None, fill=None):
    """Draw text centred on the 128 px wide screen."""
    if not draw:
        return
    font = font or FONT_MENU
    fill = fill or C["WHITE"]
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        w = bbox[2] - bbox[0]
    except Exception:
        w = len(text) * 6
    x = max(0, (LCD_W - w) // 2)
    draw.text((x, y), text, font=font, fill=fill)


def draw_header(draw, title, subtitle=None, color=None):
    """Draw the top header bar with blood-red background."""
    if not draw:
        return
    color = color or C["WHITE"]
    draw.rectangle([(0, 0), (LCD_W, 15)], fill=C["BGHDR"])
    draw.line([(0, 15), (LCD_W, 15)], fill=C["BLOOD"], width=1)
    draw_centered(draw, title, 2, FONT_TITLE, fill=color)
    if subtitle:
        draw_centered(draw, subtitle, 14, FONT_SMALL, fill=C["STEEL"])


def draw_status(draw, text, color=None):
    """Draw the bottom status bar."""
    if not draw:
        return
    color = color or C["DIM"]
    draw.rectangle([(0, LCD_H - 11), (LCD_W, LCD_H)], fill=C["BGSTATUS"])
    draw.line([(0, LCD_H - 12), (LCD_W, LCD_H - 12)], fill=C["RUST"], width=1)
    draw_centered(draw, text, LCD_H - 10, FONT_SMALL, fill=color)


def draw_menu(draw, items, selected, item_colors=None, y_start=19, item_h=13):
    """
    Draw a scrollable item list.

    items       — list of strings
    selected    — currently highlighted index
    item_colors — parallel list of fill colours (defaults to WHITE)
    """
    if not draw:
        return
    item_colors = item_colors or [C["WHITE"]] * len(items)
    max_visible = max(1, (LCD_H - y_start - 13) // item_h)

    # Sliding window around selected
    start = max(0, selected - max_visible // 2)
    end   = min(len(items), start + max_visible)
    start = max(0, end - max_visible)

    y = y_start
    for i in range(start, end):
        label = str(items[i])
        fg    = item_colors[i] if i < len(item_colors) else C["WHITE"]
        if i == selected:
            draw.rectangle([(0, y - 1), (LCD_W, y + item_h - 2)], fill=C["BGSEL"])
            draw.line([(0, y - 1), (LCD_W, y - 1)], fill=C["BLOOD"], width=1)
            fg = C["YELLOW"]
        # Truncate label to fit screen (≈21 chars at font-10)
        if len(label) > 20:
            label = label[:19] + "…"
        draw_centered(draw, label, y, FONT_MENU, fill=fg)
        y += item_h


def draw_running(draw, title, line1="", line2="", pkt_count=0, elapsed=0):
    """Draw an operation-in-progress screen."""
    if not draw:
        return
    clear_buf(draw)
    draw_header(draw, title, color=C["EMBER"])
    draw.line([(10, 30), (118, 30)], fill=C["RUST"], width=1)
    draw_centered(draw, line1[:20],      35, FONT_MENU,  fill=C["STEEL"])
    draw_centered(draw, line2[:20],      50, FONT_SMALL, fill=C["ASH"])
    draw_centered(draw, f"{pkt_count} pkts", 68, FONT_MENU, fill=C["BLOOD"])
    draw_centered(draw, f"{elapsed}s",   84, FONT_SMALL, fill=C["DIM"])
    draw_status(draw, "KEY3: STOP", color=C["ORANGE"])


def draw_result(draw, title, lines, color=None):
    """Draw a multi-line result screen (up to 6 lines)."""
    if not draw:
        return
    color = color or C["GOOD"]
    clear_buf(draw)
    draw_header(draw, title, color=color)
    y = 20
    for line in lines[:6]:
        draw.text((3, y), str(line)[:21], font=FONT_SMALL, fill=color)
        y += 10
    draw_status(draw, "KEY3: BACK", color=C["DIM"])


def draw_hosts(draw, hosts, selected, y_start=19):
    """
    Draw a scrollable host list.
    hosts — list of [ip, mac, vendor, hostname]
    """
    if not draw or not hosts:
        return
    labels = []
    colors = []
    for h in hosts:
        ip     = h[0] if h else "?"
        vendor = (h[2] if len(h) > 2 and h[2] else "")[:8]
        label  = f"{ip}" + (f" {vendor}" if vendor else "")
        labels.append(label)
        colors.append(C["WHITE"])
    draw_menu(draw, labels, selected, item_colors=colors,
              y_start=y_start, item_h=12)


# ══════════════════════════════════════════════════════════════════════════════
# ── BUTTON READER ─────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

DEBOUNCE_S = 0.22   # seconds


def read_btn(last_time):
    """
    Poll all GPIO pins once.
    Returns (button_name_or_None, updated_last_time).
    Respects DEBOUNCE_S to avoid jitter.
    """
    now = time.time()
    if now - last_time < DEBOUNCE_S:
        return None, last_time
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name, now
    return None, last_time


def wait_for_btn(allowed=None, timeout=None):
    """
    Block until one of `allowed` buttons is pressed (or any if None).
    Returns button name, or None on timeout.
    """
    allowed  = allowed or list(PINS.keys())
    deadline = (time.time() + timeout) if timeout else None
    last_t   = 0.0
    while True:
        if deadline and time.time() > deadline:
            return None
        btn, last_t = read_btn(last_t)
        if btn and btn in allowed:
            return btn
        time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════
# ── LOGGING ───────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def make_logger(name):
    """Return a log(msg) function that writes timestamped lines to /tmp."""
    path = f"/tmp/ktox_hw_{name}.log"

    def log(msg):
        try:
            with open(path, "a") as f:
                f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    return log


# ══════════════════════════════════════════════════════════════════════════════
# ── NETWORK HELPERS ───────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def get_iface_and_gateway():
    """
    Detect default network interface, its MAC, and gateway IP.
    Returns (iface, iface_mac, gateway_ip) — any may be None on failure.
    """
    iface = gw_ip = iface_mac = None
    try:
        import netifaces
        gws   = netifaces.gateways()
        entry = gws.get("default", {}).get(netifaces.AF_INET)
        if entry:
            gw_ip = entry[0]
            iface = entry[1]
    except Exception:
        pass

    if not iface:
        try:
            out = subprocess.check_output(["ip", "route"], text=True, timeout=3)
            for line in out.splitlines():
                if line.startswith("default") and "via" in line:
                    parts = line.split()
                    gw_ip = parts[parts.index("via") + 1]
                    if "dev" in parts:
                        iface = parts[parts.index("dev") + 1]
                    break
        except Exception:
            pass

    if iface:
        try:
            import netifaces
            addrs = netifaces.ifaddresses(iface)
            iface_mac = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr")
        except Exception:
            try:
                out = subprocess.check_output(
                    ["cat", f"/sys/class/net/{iface}/address"],
                    text=True, timeout=2
                )
                iface_mac = out.strip()
            except Exception:
                pass

    return iface, iface_mac, gw_ip


def do_scan_hw(network):
    """
    Run scan.scanNetwork() and return hosts list.
    Adds KTOx project root to sys.path automatically.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        import scan as _scan
        return _scan.scanNetwork(network)
    except Exception as e:
        return []


def resolve_mac(ip):
    """ARP-resolve an IP → MAC using scapy."""
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from scapy.all import Ether, ARP, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=0
        )
        for _, rcv in ans:
            return rcv.src
    except Exception:
        pass
    return None


def get_network_cidr(iface):
    """Return CIDR string (e.g. '192.168.1.0/24') for the given interface."""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        info  = addrs.get(netifaces.AF_INET, [{}])[0]
        ip    = info.get("addr", "")
        mask  = info.get("netmask", "255.255.255.0")
        if ip:
            import ipaddress
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return str(net)
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show", iface],
            text=True, timeout=2
        )
        for line in out.splitlines():
            parts = line.split()
            for p in parts:
                if "/" in p and not p.startswith("fe80"):
                    import ipaddress
                    net = ipaddress.IPv4Network(p, strict=False)
                    return str(net)
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# ── INTERACTIVE SCAN + HOST PICKER ───────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def scan_and_pick(lcd, image, draw, iface, network,
                  title="SELECT TARGET", allow_gw=False, gateway_ip=None):
    """
    Full flow: display SCANNING → run nmap → show scrollable host list →
    user picks with UP/DOWN/OK.

    Returns chosen host entry [ip, mac, vendor, hostname] or None if cancelled.
    """
    # ── scanning screen — run nmap in background thread so LCD stays alive ──
    hosts     = []
    cancelled = threading.Event()
    scan_done = threading.Event()

    def _bg_scan():
        try:
            result = do_scan_hw(network or iface)
            if not cancelled.is_set():
                hosts.extend(result)
        except Exception:
            pass
        finally:
            scan_done.set()

    threading.Thread(target=_bg_scan, daemon=True).start()

    dots   = 0
    last_t = 0.0
    while not scan_done.is_set():
        dots = (dots + 1) % 4
        clear_buf(draw)
        draw_header(draw, "KTOx", color=C["BLOOD"])
        draw_centered(draw, "SCANNING" + "." * dots, 38, FONT_MENU, fill=C["STEEL"])
        draw_centered(draw, (network or iface or "")[:20], 55, FONT_SMALL, fill=C["DIM"])
        draw_status(draw, "KEY3: cancel", color=C["DIM"])
        push(lcd, image)
        btn, last_t = read_btn(last_t)
        if btn in ("KEY3", "LEFT"):
            cancelled.set()
            scan_done.set()
            break
        time.sleep(0.3)

    if cancelled.is_set():
        return None

    if not hosts:
        clear_buf(draw)
        draw_header(draw, "KTOx", color=C["BLOOD"])
        draw_centered(draw, "NO HOSTS FOUND", 50, FONT_MENU, fill=C["ORANGE"])
        draw_status(draw, "KEY3: BACK", color=C["DIM"])
        push(lcd, image)
        wait_for_btn(["KEY3", "LEFT"])
        return None

    if not allow_gw and gateway_ip:
        hosts = [h for h in hosts if h[0] != gateway_ip]
    if not hosts:
        clear_buf(draw)
        draw_header(draw, "KTOx", color=C["BLOOD"])
        draw_centered(draw, "NO TARGETS", 50, FONT_MENU, fill=C["ORANGE"])
        draw_status(draw, "KEY3: BACK", color=C["DIM"])
        push(lcd, image)
        wait_for_btn(["KEY3", "LEFT"])
        return None

    # ── host picker ──────────────────────────────────────────────────────────
    sel   = 0
    last_t = 0.0
    while True:
        clear_buf(draw)
        draw_header(draw, title, color=C["BLOOD"])
        draw_hosts(draw, hosts, sel)
        draw_status(draw, "OK:SEL  KEY3:BACK", color=C["DIM"])
        push(lcd, image)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(hosts)
        elif btn == "DOWN":
            sel = (sel + 1) % len(hosts)
        elif btn in ("OK", "KEY_PRESS", "RIGHT"):
            return hosts[sel]
        elif btn in ("KEY3", "LEFT"):
            return None
        time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════
# ── RUNNING INDICATOR LOOP HELPER ────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def run_with_indicator(lcd, image, draw, title, op_thread,
                       stop_event, pkt_ref, subtitle=""):
    """
    While op_thread is alive, refresh the LCD with a live running indicator.
    Pressing KEY3 sets stop_event.

    pkt_ref — a list([int]) whose [0] element is the live packet counter.
    Returns True if stopped by user, False if op completed naturally.
    """
    last_t   = 0.0
    elapsed  = 0
    t_start  = time.time()
    stopped  = False

    while op_thread.is_alive():
        elapsed = int(time.time() - t_start)
        clear_buf(draw)
        draw_running(draw, title, line1=subtitle,
                     pkt_count=pkt_ref[0], elapsed=elapsed)
        push(lcd, image)

        btn, last_t = read_btn(last_t)
        if btn in ("KEY3", "LEFT"):
            stop_event.set()
            stopped = True
            break
        time.sleep(0.15)

    op_thread.join(timeout=4)
    return stopped


# ══════════════════════════════════════════════════════════════════════════════
# ── LOOT DIRECTORY ────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def loot_dir():
    """Return absolute path to ktox_loot/, creating it if needed."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d    = os.path.join(root, "ktox_loot")
    os.makedirs(d, exist_ok=True)
    return d


# ══════════════════════════════════════════════════════════════════════════════
# ── STANDARD SIGNAL HANDLERS ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def install_signal_handlers(cleanup_fn):
    """
    Install SIGINT / SIGTERM → cleanup_fn.
    Call this from every payload script's __main__ block.
    """
    signal.signal(signal.SIGINT,  lambda *_: cleanup_fn())
    signal.signal(signal.SIGTERM, lambda *_: cleanup_fn())
