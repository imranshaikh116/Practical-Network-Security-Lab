#!/usr/bin/env python3
"""
ssh_bruteforce_detect.py
------------------------
Parses /var/log/auth.log (or any syslog-format auth file) for SSH
authentication events.  Groups failures by source IP and alerts when
a configurable threshold is exceeded within a sliding time window.

Additionally detects the most dangerous pattern: a *successful* login
from an IP that previously crossed the failure threshold — the classic
brute-force-followed-by-compromise signature.

Usage
-----
    python3 ssh_bruteforce_detect.py
    python3 ssh_bruteforce_detect.py --log /var/log/auth.log
    python3 ssh_bruteforce_detect.py --threshold 5 --window 60
    python3 ssh_bruteforce_detect.py --tail            # live follow mode
    python3 ssh_bruteforce_detect.py --report report.txt

Arguments
---------
    --log FILE        Auth log to parse (default: /var/log/auth.log)
    --threshold N     Failed attempts before alerting (default: 10)
    --window SECONDS  Sliding time window in seconds (default: 300 = 5 min)
    --tail            Follow the log in real time (like tail -f)
    --report FILE     Write a findings report to FILE
    --top N           Show top N attacking IPs in summary (default: 20)

Requires
--------
    Python 3.7+   No third-party packages.
    Read access to the auth log (usually needs sudo or membership in
    the adm group on Debian/Ubuntu).

Patterns matched
----------------
    Failed password for <user> from <ip> port <port> ssh2
    Failed password for invalid user <user> from <ip> port <port> ssh2
    Invalid user <user> from <ip> port <port>
    Accepted password for <user> from <ip> port <port> ssh2
    Accepted publickey for <user> from <ip> port <port> ssh2
    Connection closed by authenticating user <user> <ip> port <port>
    Disconnected from authenticating user <user> <ip> port <port>
    pam_unix(sshd:auth): authentication failure; ... rhost=<ip>
"""

import argparse
import collections
import datetime
import re
import sys
import time
from pathlib import Path
from typing import Optional


# ── ANSI colours ─────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}" if sys.stdout.isatty() else text


# ── Regex patterns ────────────────────────────────────────────────────────────

# Syslog timestamp: "Sep 16 14:23:01" or "2024-09-16T14:23:01.000000+05:30"
TS_SYSLOG  = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)
TS_ISO     = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
)

FAIL_PATTERNS = [
    # Failed password for [invalid user] USER from IP port PORT ssh2
    re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+) port \d+"
    ),
    # Invalid user USER from IP port PORT
    re.compile(
        r"Invalid user (\S+) from ([\d.a-fA-F:]+)"
    ),
    # PAM failure line
    re.compile(
        r"pam_unix\(sshd:auth\): authentication failure;.*rhost=([\d.a-fA-F:]+)"
    ),
    # Connection closed by authenticating user
    re.compile(
        r"Disconnected from authenticating user (\S+) ([\d.a-fA-F:]+)"
    ),
]

SUCCESS_PATTERNS = [
    re.compile(
        r"Accepted (?:password|publickey) for (\S+) from ([\d.a-fA-F:]+) port \d+"
    ),
]


# ── Log event dataclass ───────────────────────────────────────────────────────

class Event:
    __slots__ = ("ts", "ip", "user", "kind", "raw")

    def __init__(
        self,
        ts: Optional[datetime.datetime],
        ip: str,
        user: str,
        kind: str,        # "fail" | "success"
        raw: str,
    ):
        self.ts   = ts
        self.ip   = ip
        self.user = user
        self.kind = kind
        self.raw  = raw

    def __repr__(self) -> str:
        ts_str = self.ts.strftime("%Y-%m-%d %H:%M:%S") if self.ts else "unknown"
        return f"Event({self.kind}, ip={self.ip}, user={self.user}, ts={ts_str})"


# ── Timestamp parsing ─────────────────────────────────────────────────────────

_CURRENT_YEAR = datetime.datetime.now().year


def parse_timestamp(line: str) -> Optional[datetime.datetime]:
    m = TS_ISO.match(line)
    if m:
        try:
            return datetime.datetime.fromisoformat(m.group(1))
        except ValueError:
            pass

    m = TS_SYSLOG.match(line)
    if m:
        try:
            return datetime.datetime.strptime(
                f"{_CURRENT_YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            pass

    return None


# ── Line parsing ──────────────────────────────────────────────────────────────

def parse_line(line: str) -> Optional[Event]:
    ts = parse_timestamp(line)

    for pat in SUCCESS_PATTERNS:
        m = pat.search(line)
        if m:
            groups = m.groups()
            user = groups[0] if len(groups) >= 2 else "unknown"
            ip   = groups[1] if len(groups) >= 2 else groups[0]
            return Event(ts, ip, user, "success", line.rstrip())

    for pat in FAIL_PATTERNS:
        m = pat.search(line)
        if m:
            groups = m.groups()
            if len(groups) == 1:
                # PAM pattern — only captures IP
                ip, user = groups[0], "unknown"
            else:
                user, ip = groups[0], groups[1]
            return Event(ts, ip, user, "fail", line.rstrip())

    return None


# ── Analysis engine ───────────────────────────────────────────────────────────

class BruteForceDetector:
    def __init__(self, threshold: int, window: int):
        self.threshold = threshold
        self.window    = window           # seconds

        # ip → deque of datetime timestamps (failures only)
        self.failures: dict[str, collections.deque] = collections.defaultdict(
            collections.deque
        )
        # ip → list of usernames attempted
        self.usernames: dict[str, set] = collections.defaultdict(set)
        # IPs that crossed the threshold this session
        self.alerted: set[str] = set()
        # ip → list of successful login events (for compromise detection)
        self.successes: dict[str, list] = collections.defaultdict(list)
        # Counter for total events
        self.total_lines   = 0
        self.total_fails   = 0
        self.total_success = 0

    def _prune(self, ip: str, now: datetime.datetime) -> None:
        """Remove failure timestamps outside the sliding window."""
        q = self.failures[ip]
        cutoff = now - datetime.timedelta(seconds=self.window)
        while q and q[0] < cutoff:
            q.popleft()

    def feed(self, event: Event) -> Optional[str]:
        """
        Process one Event.  Returns an alert string if a threshold is
        crossed or a compromise pattern is detected, else None.
        """
        if event.kind == "fail":
            self.total_fails += 1
            now = event.ts or datetime.datetime.now()
            self._prune(event.ip, now)
            self.failures[event.ip].append(now)
            self.usernames[event.ip].add(event.user)

            count = len(self.failures[event.ip])
            if count >= self.threshold and event.ip not in self.alerted:
                self.alerted.add(event.ip)
                users = ", ".join(sorted(self.usernames[event.ip]))
                return (
                    f"[BRUTE-FORCE] {event.ip}  "
                    f"{count} failures in {self.window}s window\n"
                    f"              Users tried: {users}\n"
                    f"              Last line: {event.raw[-120:]}"
                )

        elif event.kind == "success":
            self.total_success += 1
            self.successes[event.ip].append(event)

            # The dangerous pattern: success after threshold of failures
            if event.ip in self.alerted:
                ts_str = (
                    event.ts.strftime("%Y-%m-%d %H:%M:%S")
                    if event.ts else "unknown time"
                )
                return (
                    f"[COMPROMISE ] {event.ip} → user '{event.user}' "
                    f"LOGGED IN SUCCESSFULLY at {ts_str}\n"
                    f"              This IP previously triggered the "
                    f"brute-force alert!"
                )

        return None

    def summary(self) -> str:
        lines = [
            "",
            c("─── Detection Summary ───", BOLD),
            f"  Total log lines parsed : {self.total_lines}",
            f"  Total failure events   : {self.total_fails}",
            f"  Total success events   : {self.total_success}",
            f"  Unique attacking IPs   : {len(self.failures)}",
            f"  IPs over threshold     : {len(self.alerted)}",
        ]

        if self.alerted:
            lines.append(c("\n  Threshold-crossing IPs (potential attackers):", YELLOW))
            sorted_ips = sorted(
                self.alerted,
                key=lambda ip: len(self.failures[ip]),
                reverse=True,
            )
            for ip in sorted_ips:
                count = len(self.failures[ip])
                users = ", ".join(sorted(self.usernames[ip]))[:80]
                compromised = ip in self.successes
                tag = c("  ← COMPROMISED", RED) if compromised else ""
                lines.append(f"    {ip:20s}  {count:5d} failures   {users}{tag}")

        if not self.alerted:
            lines.append(c("  No IPs crossed the threshold. All clear.", GREEN))

        return "\n".join(lines)


# ── File processing ───────────────────────────────────────────────────────────

def process_file(
    path: str,
    detector: BruteForceDetector,
    report_file: Optional[str] = None,
) -> None:
    findings: list[str] = []
    p = Path(path)

    if not p.exists():
        print(c(f"ERROR: Log file not found: {path}", RED))
        sys.exit(1)

    print(c(f"Parsing: {path}", CYAN))
    print(f"Threshold: {detector.threshold} failures / "
          f"{detector.window}s window\n")

    with open(path, "r", errors="replace") as f:
        for line in f:
            detector.total_lines += 1
            event = parse_line(line)
            if event is None:
                continue

            alert = detector.feed(event)
            if alert:
                kind_colour = RED if "COMPROMISE" in alert else YELLOW
                msg = c(alert, kind_colour)
                print(msg)
                findings.append(alert)

    summary = detector.summary()
    print(summary)

    if report_file:
        with open(report_file, "w") as rf:
            rf.write(f"SSH Brute-Force Detection Report\n")
            rf.write(f"Generated: {datetime.datetime.now()}\n")
            rf.write(f"Log file : {path}\n")
            rf.write("=" * 60 + "\n\n")
            for finding in findings:
                rf.write(finding + "\n\n")
            rf.write(summary + "\n")
        print(c(f"\nReport written to: {report_file}", GREEN))


def tail_file(
    path: str,
    detector: BruteForceDetector,
) -> None:
    """Follow a log file in real time (like `tail -f`)."""
    p = Path(path)
    if not p.exists():
        print(c(f"ERROR: Log file not found: {path}", RED))
        sys.exit(1)

    print(c(f"Following: {path}  (Ctrl+C to stop)", CYAN))
    print(f"Threshold: {detector.threshold} failures / {detector.window}s window\n")

    with open(path, "r", errors="replace") as f:
        # Seek to end so we only see new lines
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                detector.total_lines += 1
                event = parse_line(line)
                if event is None:
                    continue
                alert = detector.feed(event)
                if alert:
                    kind_colour = RED if "COMPROMISE" in alert else YELLOW
                    ts_now = datetime.datetime.now().strftime("%H:%M:%S")
                    print(f"[{ts_now}] {c(alert, kind_colour)}\n")
        except KeyboardInterrupt:
            print()
            print(detector.summary())


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "SSH brute-force detector — parses auth.log and alerts "
            "when an IP exceeds a failure threshold."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log", "-l",
        default="/var/log/auth.log",
        metavar="FILE",
        help="Auth log to parse (default: /var/log/auth.log)",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=10,
        metavar="N",
        help="Failure count before alerting (default: 10)",
    )
    parser.add_argument(
        "--window", "-w",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Sliding time window in seconds (default: 300)",
    )
    parser.add_argument(
        "--tail", "-f",
        action="store_true",
        help="Follow the log file in real time",
    )
    parser.add_argument(
        "--report", "-r",
        default=None,
        metavar="FILE",
        help="Write findings report to FILE",
    )
    return parser.parse_args()


def main() -> None:
    args  = parse_args()
    detector = BruteForceDetector(
        threshold = args.threshold,
        window    = args.window,
    )

    if args.tail:
        tail_file(args.log, detector)
    else:
        process_file(args.log, detector, args.report)


if __name__ == "__main__":
    main()
