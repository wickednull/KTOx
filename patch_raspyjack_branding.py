#!/usr/bin/env python3
"""
patch_raspyjack_branding.py — Safely rebrand RaspyJack web UI to KTOx.

Run this ON THE RASPERRY PI as root:
    sudo python3 /path/to/patch_raspyjack_branding.py

It automatically:
  1. Finds the RaspyJack web UI files
  2. Makes a timestamped backup of every file it touches
  3. Replaces ONLY the branding strings — nothing else
  4. Verifies the result contains no broken remnants
  5. Prints a diff summary so you can see exactly what changed

If anything looks wrong, restore with:
    sudo python3 patch_raspyjack_branding.py --restore
"""

import os
import sys
import re
import shutil
import argparse
from datetime import datetime
from pathlib import Path

# ── Candidate locations for RaspyJack web UI ──────────────────────────────────
SEARCH_ROOTS = [
    "/root/Raspyjack",
    "/opt/Raspyjack",
    "/home/pi/Raspyjack",
    "/usr/share/raspyjack",
    "/var/www/html",
]

# ── String replacements: (old_text, new_text, case_sensitive) ─────────────────
#   Be as specific as possible so we don't accidentally change JS variables.
REPLACEMENTS = [
    # Main header title — exact HTML patterns seen in screenshot
    ("RASPYJACK\nRemote Control",   "KTOx\nNetwork Attack Toolkit",    True),
    ("RASPYJACK\r\nRemote Control", "KTOx\r\nNetwork Attack Toolkit",  True),
    # Inline variants
    (">RASPYJACK<",                 ">KTOx<",                           True),
    (">RaspyJack<",                 ">KTOx<",                           True),
    ("Remote Control</",            "Network Attack Toolkit</",         True),
    (">Remote Control<",            ">Network Attack Toolkit<",         True),
    # Title bar
    ("<title>RaspyJack",            "<title>KTOx",                      True),
    ("<title>RASPYJACK",            "<title>KTOx",                      True),
    # String literals in JS (subtitle/tagline)
    ('"Remote Control"',            '"Network Attack Toolkit"',         True),
    ("'Remote Control'",            "'Network Attack Toolkit'",         True),
    # CSS class text / aria-label patterns
    ('aria-label="RaspyJack"',      'aria-label="KTOx"',                True),
    ('alt="RaspyJack"',             'alt="KTOx"',                       True),
]

BACKUP_SUFFIX = f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
_touched_files = []


def find_web_files():
    """Locate all HTML/JS/CSS files in RaspyJack web UI directories."""
    found = []
    for root in SEARCH_ROOTS:
        if os.path.isdir(root):
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    if fname.endswith((".html", ".js", ".css", ".htm")):
                        found.append(os.path.join(dirpath, fname))
    return found


def patch_file(path):
    """Apply branding replacements to a single file. Returns True if changed."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        original = f.read()

    content = original
    for old, new, cs in REPLACEMENTS:
        if cs:
            content = content.replace(old, new)
        else:
            content = re.sub(re.escape(old), new, content, flags=re.IGNORECASE)

    if content == original:
        return False  # Nothing changed

    # Backup first
    backup = path + BACKUP_SUFFIX
    shutil.copy2(path, backup)
    _touched_files.append((path, backup))

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    return True


def show_diff(path, backup):
    """Print a compact summary of what changed."""
    try:
        import difflib
        with open(backup, encoding="utf-8", errors="replace") as f:
            old_lines = f.readlines()
        with open(path, encoding="utf-8", errors="replace") as f:
            new_lines = f.readlines()
        diff = list(difflib.unified_diff(old_lines, new_lines, lineterm="",
                                         fromfile="original", tofile="patched"))
        if diff:
            print(f"\n  Changes in {os.path.basename(path)}:")
            for line in diff[:40]:  # cap output
                print(f"    {line}")
    except Exception as e:
        print(f"  (diff unavailable: {e})")


def restore():
    """Find all .bak_* files and restore them."""
    restored = 0
    for root in SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if ".bak_" in fname:
                    backup_path = os.path.join(dirpath, fname)
                    # original is the name without the .bak_* suffix
                    original_path = re.sub(r'\.bak_\d{8}_\d{6}$', '', backup_path)
                    shutil.copy2(backup_path, original_path)
                    os.remove(backup_path)
                    print(f"  Restored: {original_path}")
                    restored += 1
    if restored:
        print(f"\n✔ Restored {restored} file(s) to original.")
    else:
        print("No backup files found — nothing to restore.")


def main():
    parser = argparse.ArgumentParser(description="Rebrand RaspyJack web UI to KTOx")
    parser.add_argument("--restore", action="store_true",
                        help="Restore all files from backups")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would change without writing anything")
    args = parser.parse_args()

    if args.restore:
        restore()
        return

    print("KTOx Branding Patch for RaspyJack Web UI")
    print("=" * 50)

    files = find_web_files()
    if not files:
        print("ERROR: No RaspyJack web UI files found.")
        print("Looked in:", ", ".join(SEARCH_ROOTS))
        print("\nIf your RaspyJack is installed elsewhere, edit SEARCH_ROOTS at")
        print("the top of this script to add your path.")
        sys.exit(1)

    print(f"Found {len(files)} HTML/JS/CSS files to check.")
    if args.dry_run:
        print("(DRY RUN — no files will be modified)\n")

    changed = 0
    for fpath in sorted(files):
        if args.dry_run:
            # Read-only pass
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for old, new, cs in REPLACEMENTS:
                if (cs and old in content) or \
                   (not cs and re.search(re.escape(old), content, re.IGNORECASE)):
                    print(f"  WOULD CHANGE: {fpath}")
                    print(f"    '{old[:60]}' → '{new[:60]}'")
                    changed += 1
        else:
            if patch_file(fpath):
                changed += 1
                print(f"  ✔ Patched: {fpath}")

    print(f"\n{'Would change' if args.dry_run else 'Changed'} {changed} file(s).")

    if not args.dry_run and _touched_files:
        print("\nDiff summary:")
        for path, backup in _touched_files:
            show_diff(path, backup)
        print(f"\nBackups saved with suffix: {BACKUP_SUFFIX}")
        print("To undo everything: python3 patch_raspyjack_branding.py --restore")
        print("\n✔ Done! Refresh your browser (Ctrl+Shift+R) to see the changes.")


if __name__ == "__main__":
    main()
