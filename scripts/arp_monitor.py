#!/usr/bin/env python3
"""Monitor ARP/neighbor changes and alert when a host changes MAC address.

This script is intended for educational lab use in a controlled environment.
It watches Linux neighbor entries through `ip neigh show` and warns when a
known IP address appears with a different MAC address than previously observed.
"""

import argparse
import subprocess
import sys
import time
from collections import defaultdict


def get_arp_table(command_output=None):
    """Return a dict of IP -> MAC from either a live command or pre-captured text."""
    if command_output is not None:
        text = command_output
    else:
        try:
            text = subprocess.check_output(["ip", "neigh", "show"], text=True, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            try:
                text = subprocess.check_output(["arp", "-an"], text=True, stderr=subprocess.STDOUT)
            except Exception as exc:  # pragma: no cover
                raise RuntimeError(f"Unable to gather neighbor info: {exc}") from exc

    neighbors = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            ip_index = 0
            mac_index = parts.index("lladdr") + 1
            if mac_index < len(parts):
                ip = parts[ip_index]
                mac = parts[mac_index]
                neighbors[ip] = mac.lower()
        elif len(parts) >= 4 and parts[0].startswith("?"):
            # `arp -an` output format: ? (192.168.56.10) at 00:11:22:33:44:55 [ether] on eth0
            if "at" in parts:
                ip = parts[1].strip("()")
                mac = parts[2].lower()
                neighbors[ip] = mac

    return neighbors


def monitor(interval=3, repeat=True, source_file=None):
    observed = {}
    print("[+] Starting ARP monitor. Press Ctrl+C to stop.")

    while True:
        try:
            if source_file:
                with open(source_file, "r", encoding="utf-8") as handle:
                    table = get_arp_table(handle.read())
            else:
                table = get_arp_table()
        except Exception as exc:
            print(f"[-] Error collecting ARP data: {exc}")
            if not repeat:
                break
            time.sleep(interval)
            continue

        for ip, mac in table.items():
            previous = observed.get(ip)
            if previous and previous != mac:
                print(f"[ALERT] IP {ip} changed from {previous} to {mac}")
            observed[ip] = mac

        for ip in list(observed):
            if ip not in table:
                print(f"[INFO] IP {ip} disappeared from neighbor table")
                del observed[ip]

        time.sleep(interval)
        if not repeat:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor for unexpected ARP/MAC changes in a lab network.")
    parser.add_argument("--interval", type=int, default=3, help="Seconds between scans (default: 3)")
    parser.add_argument("--once", action="store_true", help="Run one scan only instead of monitoring continuously")
    parser.add_argument("--source-file", help="Read neighbor data from a text file instead of live system state")
    args = parser.parse_args()

    try:
        monitor(interval=args.interval, repeat=not args.once, source_file=args.source_file)
    except KeyboardInterrupt:
        print("\n[+] Stopping ARP monitor.")
        sys.exit(0)
