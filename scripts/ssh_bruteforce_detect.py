#!/usr/bin/env python3
"""Detect SSH brute-force attempts in `/var/log/auth.log` style files.

This script is intended for ethical lab use. It scans log lines for failed SSH
password attempts and raises an alert when a source IP exceeds the configured
threshold within a sliding time window.
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime


FAIL_PATTERNS = [
    r"Failed password for invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    r"error: maximum authentication attempts exceeded for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)",
]


def parse_timestamp(line):
    """Try to parse a log line timestamp in the form 'Jan 01 12:34:56' or '2025-01-01T12:34:56Z'."""
    candidates = [
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})",
        r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)",
    ]

    for pattern in candidates:
        match = re.match(pattern, line)
        if match:
            if "iso" in match.groupdict():
                return datetime.fromisoformat(match.group("iso").replace("Z", "+00:00"))
            # We only need a rough timestamp for ordering here; month/day/time without year is fine.
            try:
                return datetime.strptime(f"{datetime.now().year} {match.group(0)}", "%Y %b %d %H:%M:%S")
            except ValueError:
                return None
    return None


def extract_failures(log_lines):
    failures = []
    for line in log_lines:
        for pattern in FAIL_PATTERNS:
            match = re.search(pattern, line)
            if match:
                failures.append((match.group("ip"), line.strip()))
                break
    return failures


def detect_bruteforce(path, threshold=5, window_seconds=60):
    records = defaultdict(list)

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            for pattern in FAIL_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    ip = match.group("ip")
                    ts = parse_timestamp(line)
                    if ts is not None:
                        records[ip].append(ts)
                    else:
                        records[ip].append(datetime.now())
                    break

    suspicious = []
    for ip, times in records.items():
        times.sort()
        active_window = []
        for ts in times:
            active_window.append(ts)
            while active_window and (ts - active_window[0]).total_seconds() > window_seconds:
                active_window.pop(0)
            if len(active_window) >= threshold:
                suspicious.append({
                    "ip": ip,
                    "count": len(active_window),
                    "window_seconds": window_seconds,
                    "latest": ts,
                })
                break

    return suspicious


def main():
    parser = argparse.ArgumentParser(description="Detect likely SSH brute-force attacks from auth log data.")
    parser.add_argument("path", help="Path to auth log or similar file")
    parser.add_argument("--threshold", type=int, default=5, help="Number of failed attempts within the window before alert")
    parser.add_argument("--window", type=int, default=60, help="Window size in seconds for brute-force detection")
    args = parser.parse_args()

    try:
        suspicious = detect_bruteforce(args.path, threshold=args.threshold, window_seconds=args.window)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.path}")
        sys.exit(1)

    if not suspicious:
        print("[+] No SSH brute-force activity exceeds the configured threshold.")
        return

    print("[ALERT] SSH brute-force activity detected:")
    for item in suspicious:
        print(f"  - IP {item['ip']}: {item['count']} failed attempts in {item['window_seconds']} seconds")


if __name__ == "__main__":
    main()
