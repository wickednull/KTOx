#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# hw/ktox_hw_defense.py — KTOx Purple Team Defense Engine (Hardware GUI)
#
# Wraps ktox_defense.py with RaspyJack LCD/GPIO interface.
# All defense operations are backed up before application and
# can be rolled back from the ROLLBACK menu entry.
#
# Defense functions covered:
#   ARP Harden · LLMNR Disable · SMB Signing · TLS/HTTPS
#   DNS-over-TLS · Cleartext Audit · Segmentation Guide
#   Security Audit · ARP Watch (passive) · Rollback All
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
    scan_and_pick, do_scan_hw,
    install_signal_handlers, make_logger, loot_dir,
    C, FONT_TITLE, FONT_MENU, FONT_SMALL, LCD_W, LCD_H,
)

log = make_logger("defense")

LCD = IMAGE = DRAW = None
RUNNING = True

MENU_ITEMS = [
    "ARP HARDEN",
    "LLMNR DISABLE",
    "SMB SIGNING",
    "TLS/HTTPS",
    "DNS OVER TLS",
    "CLEARTEXT AUDIT",
    "SEGMENT GUIDE",
    "SECURITY AUDIT",
    "ARP WATCH",
    "ROLLBACK ALL",
    "< BACK",
]
MENU_COLORS = [
    C["GOOD"],  C["GOOD"],  C["GOOD"],  C["GOOD"],
    C["GOOD"],  C["ASH"],   C["ASH"],   C["GOOD"],
    C["STEEL"], C["ORANGE"], C["DIM"],
]


def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    hw_cleanup(LCD)
    sys.exit(0)


def _try_import_def():
    try:
        import ktox_defense as d
        return d
    except Exception as e:
        log(f"import ktox_defense failed: {e}")
        return None


def _confirm(title, msg_lines):
    """Show a confirmation dialog. Returns True if OK pressed."""
    clear_buf(DRAW)
    draw_header(DRAW, title, color=C["ORANGE"])
    y = 22
    for line in msg_lines[:4]:
        draw_centered(DRAW, line[:20], y, FONT_SMALL, fill=C["ASH"])
        y += 12
    draw_status(DRAW, "OK:CONFIRM KEY3:CANCEL", color=C["DIM"])
    push(LCD, IMAGE)
    btn = wait_for_btn(["OK", "KEY_PRESS", "KEY3", "LEFT"])
    return btn in ("OK", "KEY_PRESS")


def _run_defense_op(title, func, success_lines, error_prefix="ERR"):
    """Run func() synchronously, show result on LCD."""
    clear_buf(DRAW)
    draw_header(DRAW, title, color=C["GOOD"])
    draw_centered(DRAW, "applying...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)
    try:
        func()
        draw_result(DRAW, title, success_lines, color=C["GOOD"])
    except Exception as e:
        log(f"{error_prefix} error: {e}")
        draw_result(DRAW, f"{error_prefix}", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
# ── DEFENSE OPERATIONS ────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def op_arp_harden(d, iface, network, gw_ip, gw_mac):
    """Apply static ARP entries for all known hosts."""
    if not _confirm("ARP HARDEN",
                    ["Apply static ARP", "entries for all", "known hosts?",
                     "Backup created."]):
        return

    clear_buf(DRAW)
    draw_header(DRAW, "ARP HARDEN", color=C["GOOD"])
    draw_centered(DRAW, "scanning...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    hosts = do_scan_hw(network)
    if not hosts:
        draw_result(DRAW, "ARP HARDEN", ["no hosts found"], color=C["ORANGE"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3", "LEFT"])
        return

    clear_buf(DRAW)
    draw_header(DRAW, "ARP HARDEN", color=C["GOOD"])
    draw_centered(DRAW, f"hardening {len(hosts)}", 50, FONT_MENU, fill=C["STEEL"])
    draw_centered(DRAW, "hosts...", 65, FONT_SMALL, fill=C["DIM"])
    push(LCD, IMAGE)

    try:
        hardener = d.ArpSpoofDefense(iface=iface, loot_dir=loot_dir())
        hardener.harden(hosts=hosts, gateway_ip=gw_ip, gateway_mac=gw_mac)
        log(f"ARP_HARDEN_DONE hosts={len(hosts)}")
        draw_result(DRAW, "ARP HARDEN",
                    [f"{len(hosts)} entries set", "static ARP active",
                     "script: loot/arp_harden.sh"],
                    color=C["GOOD"])
    except Exception as e:
        log(f"arp_harden error: {e}")
        draw_result(DRAW, "HARDEN ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_llmnr_disable(d):
    """Disable LLMNR and NBT-NS via systemd-resolved + iptables."""
    if not _confirm("LLMNR", ["Disable LLMNR &", "NBT-NS?",
                               "systemd-resolved", "will be updated."]):
        return

    def _do():
        defender = d.LLMNRDefense(loot_dir=loot_dir())
        defender.disable_llmnr()
        defender.disable_nbtns()
        log("LLMNR_DISABLED")

    _run_defense_op("LLMNR", _do,
                    ["LLMNR disabled", "NBT-NS disabled", "Backup saved"],
                    "LLMNR ERR")


def op_smb_signing(d):
    """Enforce mandatory SMB signing in smb.conf."""
    if not _confirm("SMB SIGNING", ["Enforce mandatory", "SMB signing?",
                                     "smb.conf backed up", "before change."]):
        return

    def _do():
        defender = d.SMBDefense(loot_dir=loot_dir())
        defender.enforce_signing()
        log("SMB_SIGNING_ENFORCED")

    _run_defense_op("SMB SIGN", _do,
                    ["SMB signing", "mandatory", "smb.conf updated"],
                    "SMB ERR")


def op_tls(d):
    """Configure HSTS + HTTPS redirect + Secure cookie flags."""
    if not _confirm("TLS/HTTPS", ["Configure HSTS,", "HTTPS redirect,",
                                   "Secure cookies?"]):
        return

    def _do():
        defender = d.SSLDefense(loot_dir=loot_dir())
        defender.configure_hsts()
        defender.configure_https_redirect()
        defender.configure_secure_cookies()
        log("TLS_CONFIGURED")

    _run_defense_op("TLS", _do,
                    ["HSTS enabled", "HTTPS redirect", "Secure cookies set"],
                    "TLS ERR")


def op_dot(d):
    """Configure DNS-over-TLS."""
    if not _confirm("DNS-over-TLS", ["Configure DoT?", "Verify DoT works",
                                      "before committing."]):
        return

    def _do():
        defender = d.DNSDefense(loot_dir=loot_dir())
        defender.configure_dot()
        log("DoT_CONFIGURED")

    _run_defense_op("DNS DoT", _do,
                    ["DoT configured", "DNS encrypted"],
                    "DoT ERR")


def op_cleartext_audit(d, iface):
    """Audit cleartext protocol exposure (FTP/Telnet/POP3/IMAP/Redis)."""
    clear_buf(DRAW)
    draw_header(DRAW, "CLEAR AUDIT", color=C["ASH"])
    draw_centered(DRAW, "auditing...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        auditor  = d.CredentialDefense(iface=iface, loot_dir=loot_dir())
        findings = auditor.audit()
        n_issues = len(findings) if findings else 0
        log(f"CLEARTEXT_AUDIT issues={n_issues}")
        color = C["BLOOD"] if n_issues else C["GOOD"]
        draw_result(DRAW, "AUDIT DONE",
                    [f"{n_issues} exposures", "saved to loot"],
                    color=color)
    except Exception as e:
        log(f"cleartext_audit error: {e}")
        draw_result(DRAW, "AUDIT ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_segment_guide(d):
    """Show network segmentation guidance."""
    clear_buf(DRAW)
    draw_header(DRAW, "SEGMENT", color=C["ASH"])
    try:
        defender = d.NetworkSegmentDefense(loot_dir=loot_dir())
        guide    = defender.get_guide()
        lines    = str(guide).splitlines()[:6] if guide else ["See loot/segment.txt"]
        log("SEGMENT_GUIDE_SHOWN")
        draw_result(DRAW, "SEGMENT", lines, color=C["ASH"])
    except Exception as e:
        log(f"segment_guide error: {e}")
        draw_result(DRAW, "SEGMENT", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_security_audit(d, iface, hosts, gw_ip, gw_mac):
    """Full purple team security posture assessment."""
    if not _confirm("SEC AUDIT", ["Full security", "posture audit?",
                                   "Writes audit_*.json", "to loot/"]):
        return

    clear_buf(DRAW)
    draw_header(DRAW, "SEC AUDIT", color=C["GOOD"])
    draw_centered(DRAW, "running checks...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        auditor = d.SecurityAudit(
            iface=iface, hosts=hosts,
            gateway_ip=gw_ip, gateway_mac=gw_mac,
            loot_dir=loot_dir()
        )
        result  = auditor.run()
        score   = result.get("score", "?") if isinstance(result, dict) else "?"
        issues  = result.get("issues", []) if isinstance(result, dict) else []
        n_crit  = sum(1 for i in issues if isinstance(i, dict) and i.get("severity") == "critical")
        log(f"SEC_AUDIT_DONE score={score} issues={len(issues)} critical={n_crit}")
        color = C["BLOOD"] if n_crit else (C["ORANGE"] if issues else C["GOOD"])
        draw_result(DRAW, "AUDIT DONE",
                    [f"Score: {score}", f"{len(issues)} issues", f"{n_crit} critical",
                     "saved to loot"],
                    color=color)
    except Exception as e:
        log(f"sec_audit error: {e}")
        draw_result(DRAW, "AUDIT ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_arp_watch(iface, gw_ip):
    """Passive ARP monitoring — watch for spoofing/new MACs."""
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
    alerts    = [0]
    stop      = threading.Event()

    def _pkt_handler(pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                alerts[0] += 1
                log(f"ARP_SPOOF_DETECTED ip={ip} old={arp_table[ip]} new={mac}")
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
        draw_centered(DRAW, f"{len(arp_table)} hosts",   35, FONT_MENU, fill=C["WHITE"])
        draw_centered(DRAW, f"{alerts[0]} alerts",       52, FONT_MENU,
                      fill=C["BLOOD"] if alerts[0] else C["GOOD"])
        draw_centered(DRAW, f"{elapsed}s",               70, FONT_SMALL, fill=C["DIM"])
        draw_status(DRAW, "KEY3: STOP", color=C["DIM"])
        push(LCD, IMAGE)
        btn, last_t = read_btn(last_t)
        if btn in ("KEY3", "LEFT"):
            stop.set()
        time.sleep(0.2)

    t.join(timeout=3)
    log(f"ARP_WATCH_STOP alerts={alerts[0]}")
    draw_result(DRAW, "WATCH DONE",
                [f"{alerts[0]} alerts", f"{len(arp_table)} seen"],
                color=C["GOOD"] if alerts[0] == 0 else C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


def op_rollback(d):
    """Roll back all defense file modifications."""
    if not _confirm("ROLLBACK", ["Restore all", "backed-up files?",
                                  "This undoes all", "defense changes."]):
        return

    clear_buf(DRAW)
    draw_header(DRAW, "ROLLBACK", color=C["ORANGE"])
    draw_centered(DRAW, "restoring...", 50, FONT_MENU, fill=C["STEEL"])
    push(LCD, IMAGE)

    try:
        d.rollback_all(loot_dir=loot_dir())
        log("ROLLBACK_COMPLETE")
        draw_result(DRAW, "ROLLBACK",
                    ["All files restored", "from backups"], color=C["GOOD"])
    except Exception as e:
        log(f"rollback error: {e}")
        draw_result(DRAW, "ROLLBACK ERR", [str(e)[:20]], color=C["BLOOD"])
    push(LCD, IMAGE)
    wait_for_btn(["KEY3", "LEFT", "OK"])


# ══════════════════════════════════════════════════════════════════════════════
def main():
    global LCD, IMAGE, DRAW

    d = _try_import_def()
    if not d:
        clear_buf(DRAW)
        draw_header(DRAW, "DEFENSE", color=C["BLOOD"])
        draw_centered(DRAW, "ktox_defense", 40, FONT_MENU, fill=C["ORANGE"])
        draw_centered(DRAW, "not found", 55, FONT_SMALL, fill=C["ORANGE"])
        push(LCD, IMAGE)
        time.sleep(3)
        return

    iface, iface_mac, gw_ip = get_iface_and_gateway()
    if not iface:
        clear_buf(DRAW)
        draw_header(DRAW, "DEFENSE", color=C["BLOOD"])
        draw_centered(DRAW, "no interface!", 50, FONT_MENU, fill=C["BLOOD"])
        push(LCD, IMAGE)
        wait_for_btn(["KEY3"])
        return

    network = get_network_cidr(iface)

    # Pre-scan for host-dependent operations
    _hosts_cache   = []
    _hosts_scanned = False
    gw_mac         = None

    def _ensure_hosts():
        nonlocal _hosts_cache, _hosts_scanned, gw_mac
        if _hosts_scanned:
            return
        clear_buf(DRAW)
        draw_header(DRAW, "DEFENSE", color=C["GOOD"])
        draw_centered(DRAW, "scanning hosts...", 50, FONT_MENU, fill=C["STEEL"])
        push(LCD, IMAGE)
        _hosts_cache   = do_scan_hw(network) or []
        _hosts_scanned = True
        for h in _hosts_cache:
            if h[0] == gw_ip:
                gw_mac = h[1]
                break
        if not gw_mac:
            from ktox_hw_utils import resolve_mac
            gw_mac = resolve_mac(gw_ip) or ""

    sel    = 0
    last_t = 0.0

    while RUNNING:
        clear_buf(DRAW)
        draw_header(DRAW, "DEFENSE", color=C["GOOD"])
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

            if choice == "ARP HARDEN":
                _ensure_hosts()
                op_arp_harden(d, iface, network, gw_ip, gw_mac)

            elif choice == "LLMNR DISABLE":
                op_llmnr_disable(d)

            elif choice == "SMB SIGNING":
                op_smb_signing(d)

            elif choice == "TLS/HTTPS":
                op_tls(d)

            elif choice == "DNS OVER TLS":
                op_dot(d)

            elif choice == "CLEARTEXT AUDIT":
                op_cleartext_audit(d, iface)

            elif choice == "SEGMENT GUIDE":
                op_segment_guide(d)

            elif choice == "SECURITY AUDIT":
                _ensure_hosts()
                op_security_audit(d, iface, _hosts_cache, gw_ip, gw_mac)

            elif choice == "ARP WATCH":
                op_arp_watch(iface, gw_ip)

            elif choice == "ROLLBACK ALL":
                op_rollback(d)

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
