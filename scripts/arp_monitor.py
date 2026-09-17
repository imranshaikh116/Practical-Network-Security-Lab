#!/usr/bin/env python3
"""
arp_monitor.py
--------------
Monitors the kernel ARP/neighbour table by polling `ip neigh` at a
configurable interval.  Alerts whenever a previously-seen IP address
starts resolving to a *different* MAC address — the primary indicator
of ARP spoofing on a local-link segment.

Usage
-----
    sudo python3 arp_monitor.py                  # default: poll every 5 s
    sudo python3 arp_monitor.py --interval 2     # poll every 2 s
    sudo python3 arp_monitor.py --iface eth0     # restrict to one interface
    sudo python3 arp_monitor.py --log arp.log    # write alerts to a file
    sudo python3 arp_monitor.py --whitelist whitelist.txt

Whitelist file format (one entry per line):
    192.168.56.1 aa:bb:cc:dd:ee:ff
    192.168.56.20 11:22:33:44:55:66

Requires
--------
    Python 3.7+  (no third-party packages — uses only stdlib + iproute2)
    Run as root or with CAP_NET_ADMIN so `ip neigh` returns all entries.

Lab use
-------
    Start this on your Kali or defender VM *before* running any MITM
    exercise.  The first MAC binding seen for each IP is treated as
    the trusted baseline.  Any subsequent change triggers an alert.
"""

import argparse
import datetime
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path


# ── ANSI colours (disabled automatically when stdout is not a tty) ──────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def colourise(text: str, colour: str) -> str:
    if sys.stdout.isatty():
        return f"{colour}{text}{RESET}"
    return text


# ── Logging ──────────────────────────────────────────────────────────────────

log_file = None


def log(message: str) -> None:
    """Print to stdout and optionally append to log file."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line)
    if log_file:
        with open(log_file, "a") as f:
            f.write(line + "\n")


# ── Neighbour table parsing ───────────────────────────────────────────────────

def get_neighbours(iface: str = None) -> dict[str, dict]:
    """
    Run `ip neigh show` and parse into a dict keyed by IP address.

    Returns
    -------
    {
        "192.168.56.1": {
            "mac": "aa:bb:cc:dd:ee:ff",
            "dev": "eth0",
            "state": "REACHABLE"
        },
        ...
    }
    Only entries that have a resolved MAC address are included.
    """
    cmd = ["ip", "neigh", "show"]
    if iface:
        cmd += ["dev", iface]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as exc:
        log(f"ERROR: `ip neigh show` failed: {exc.stderr.strip()}")
        return {}
    except FileNotFoundError:
        log("ERROR: `ip` command not found. Install iproute2.")
        sys.exit(1)

    neighbours: dict[str, dict] = {}

    for line in result.stdout.splitlines():
        # Example line:
        # 192.168.56.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        # 192.168.56.99 dev eth0  FAILED
        parts = line.split()
        if len(parts) < 4:
            continue

        ip   = parts[0]
        dev  = parts[2] if len(parts) > 2 else "?"
        mac  = None
        state = parts[-1]

        # MAC is preceded by the keyword 'lladdr'
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            mac = parts[idx + 1]

        if mac is None:
            # Entry with no resolved MAC (FAILED/INCOMPLETE) — skip
            continue

        neighbours[ip] = {"mac": mac, "dev": dev, "state": state}

    return neighbours


# ── Whitelist loading ─────────────────────────────────────────────────────────

def load_whitelist(path: str) -> dict[str, str]:
    """
    Load trusted IP→MAC pairs from a text file.
    Lines starting with # are comments.

    Returns {ip: mac, ...} with MACs normalised to lower-case.
    """
    whitelist: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        log(f"WARNING: whitelist file '{path}' not found — ignoring.")
        return whitelist

    for raw_line in p.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip, mac = parts[0], parts[1].lower()
            whitelist[ip] = mac

    log(f"Loaded {len(whitelist)} whitelist entries from {path}")
    return whitelist


# ── Core monitor loop ────────────────────────────────────────────────────────

def monitor(interval: float, iface: str, whitelist: dict[str, str]) -> None:
    """
    Poll the neighbour table every `interval` seconds.
    Maintain a baseline of first-seen IP→MAC bindings.
    Alert on any change.
    """
    baseline: dict[str, str] = {}        # ip → mac (first seen / trusted)
    change_count: defaultdict[str, int] = defaultdict(int)

    log(colourise("ARP monitor started.", GREEN))
    if iface:
        log(f"Watching interface: {iface}")
    log(f"Poll interval: {interval}s")
    log("Press Ctrl+C to stop.\n")

    # If a whitelist was provided, pre-populate the baseline so any deviation
    # from the known good state triggers an alert immediately.
    for ip, mac in whitelist.items():
        baseline[ip] = mac
        log(f"  Baseline (whitelist): {ip:20s} → {mac}")

    if whitelist:
        print()

    try:
        while True:
            neighbours = get_neighbours(iface)

            for ip, info in neighbours.items():
                mac   = info["mac"]
                dev   = info["dev"]
                state = info["state"]

                if ip not in baseline:
                    # First time we've seen this IP — record it
                    baseline[ip] = mac
                    log(
                        colourise(
                            f"[NEW]   {ip:20s} → {mac}  "
                            f"(dev={dev}, state={state})",
                            CYAN
                        )
                    )

                elif baseline[ip] != mac:
                    # MAC changed for a known IP — this is the alert condition
                    change_count[ip] += 1
                    alert = (
                        f"[ALERT] ARP binding CHANGED for {ip}\n"
                        f"        was : {baseline[ip]}\n"
                        f"        now : {mac}\n"
                        f"        dev : {dev}  state: {state}\n"
                        f"        changes detected for this IP: "
                        f"{change_count[ip]}"
                    )
                    log(colourise(alert, RED))

                    # Optionally update baseline so we only alert on *each*
                    # subsequent change rather than every poll:
                    # baseline[ip] = mac

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        log("Monitor stopped by user.")
        _print_summary(baseline, change_count)


def _print_summary(
    baseline: dict[str, str],
    change_count: defaultdict[str, int]
) -> None:
    print()
    log(colourise("─── Session summary ───", BOLD))
    log(f"  Total tracked IPs : {len(baseline)}")
    log(f"  IPs with changes  : {len(change_count)}")
    if change_count:
        log(colourise("  Suspicious IPs:", YELLOW))
        for ip, count in sorted(change_count.items()):
            log(f"    {ip:20s}  {count} change(s)")


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ARP / neighbour-table monitor — alerts on MAC binding changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Polling interval in seconds (default: 5)",
    )
    parser.add_argument(
        "--iface", "-I",
        default=None,
        metavar="INTERFACE",
        help="Restrict monitoring to a specific interface (e.g. eth0)",
    )
    parser.add_argument(
        "--log", "-l",
        default=None,
        metavar="FILE",
        help="Append all output to this log file as well as stdout",
    )
    parser.add_argument(
        "--whitelist", "-w",
        default=None,
        metavar="FILE",
        help="File of trusted IP→MAC pairs to use as the initial baseline",
    )
    return parser.parse_args()


def main() -> None:
    global log_file

    args = parse_args()
    log_file = args.log

    whitelist: dict[str, str] = {}
    if args.whitelist:
        whitelist = load_whitelist(args.whitelist)

    monitor(
        interval  = args.interval,
        iface     = args.iface,
        whitelist = whitelist,
    )


if __name__ == "__main__":
    main()
