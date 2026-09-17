#!/usr/bin/env python3
"""
dns_anomaly.py
--------------
Detects DNS anomalies by monitoring live DNS traffic (or analysing a
saved .pcap file) and flagging:

  1. ANSWER MISMATCH  — the same domain resolves to different IPs
                        within a configurable time window (cache-poisoning
                        or rogue-resolver indicator).

  2. MULTIPLE ANSWERS — a single query receives more than one response
                        packet (race-injection indicator).

  3. UNEXPECTED SOURCE — a DNS answer arrives from an IP that is not
                         your configured resolver (rogue-server indicator).

  4. HIGH NXDOMAIN RATE — unusually many non-existent domain responses
                           from a single source (recon / DGA indicator).

  5. ANSWER MISMATCH vs AUTHORITATIVE — optionally cross-check every
                                         resolved IP against a live dig
                                         query to the public authoritative
                                         server (detects local spoofing).

Usage
-----
    # Live capture on eth0 (requires root + scapy):
    sudo python3 dns_anomaly.py --iface eth0

    # Analyse a saved pcap:
    python3 dns_anomaly.py --pcap capture.pcap

    # Specify the trusted resolver (default: reads /etc/resolv.conf):
    sudo python3 dns_anomaly.py --iface eth0 --resolver 192.168.56.30

    # Enable authoritative cross-check (makes live DNS queries):
    sudo python3 dns_anomaly.py --iface eth0 --verify

    # Log to file:
    sudo python3 dns_anomaly.py --iface eth0 --log dns_alerts.log

Requires
--------
    pip install scapy
    (Scapy is pre-installed on Kali Linux.)
    Root / CAP_NET_RAW for live capture.
"""

import argparse
import collections
import datetime
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

try:
    from scapy.all import (
        DNS, DNSQR, DNSRR,
        IP, UDP,
        PcapReader,
        conf as scapy_conf,
        sniff,
    )
    scapy_conf.verb = 0   # suppress scapy noise
except ImportError:
    print(
        "ERROR: scapy is not installed.\n"
        "Install it with:  pip install scapy\n"
        "On Kali Linux it is pre-installed — try: sudo python3 dns_anomaly.py"
    )
    sys.exit(1)


# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}" if sys.stdout.isatty() else text


# ── Logging ───────────────────────────────────────────────────────────────────

_log_fh = None


def log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if _log_fh:
        _log_fh.write(line + "\n")
        _log_fh.flush()


# ── Resolver detection ────────────────────────────────────────────────────────

def detect_resolver() -> Optional[str]:
    """Read the first nameserver from /etc/resolv.conf."""
    p = Path("/etc/resolv.conf")
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    return None


# ── Authoritative cross-check ─────────────────────────────────────────────────

def authoritative_lookup(domain: str) -> set[str]:
    """
    Perform a live A-record lookup using dig +short against the public
    authoritative server chain (+trace would be slower).  Returns the
    set of IPs returned, or an empty set on failure.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", domain],
            capture_output=True,
            text=True,
            timeout=5,
        )
        ips: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            # dig +short may return CNAMEs before the IP; skip non-IPs
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                ips.add(line)
        return ips
    except Exception:
        return set()


# ── Detector state ────────────────────────────────────────────────────────────

class DnsAnomalyDetector:
    def __init__(
        self,
        resolver: Optional[str],
        mismatch_window: int = 60,
        nxdomain_threshold: int = 20,
        verify: bool = False,
    ):
        self.resolver           = resolver
        self.mismatch_window    = mismatch_window   # seconds
        self.nxdomain_threshold = nxdomain_threshold
        self.verify             = verify

        # domain → list of (timestamp, answer_set, src_ip)
        self.answer_history: dict[str, list] = collections.defaultdict(list)

        # qid → (timestamp, src_ip_of_query, domain)
        self.pending_queries: dict[int, tuple] = {}

        # qid → list of response src IPs
        self.response_sources: dict[int, list] = collections.defaultdict(list)

        # src_ip → deque of nxdomain timestamps
        self.nxdomain_counts: dict[str, collections.deque] = (
            collections.defaultdict(collections.deque)
        )
        self.nxdomain_alerted: set[str] = set()

        # Counters
        self.packets_seen     = 0
        self.queries_seen     = 0
        self.responses_seen   = 0
        self.alerts_raised    = 0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _prune_history(self, domain: str, now: datetime.datetime) -> None:
        cutoff = now - datetime.timedelta(seconds=self.mismatch_window)
        self.answer_history[domain] = [
            entry for entry in self.answer_history[domain]
            if entry[0] >= cutoff
        ]

    def _extract_a_records(self, pkt) -> set[str]:
        """Return the set of A-record IPs from a DNS response packet."""
        ips: set[str] = set()
        if pkt.haslayer(DNSRR):
            ans = pkt[DNS].an
            while ans:
                try:
                    if ans.type == 1:   # A record
                        ips.add(ans.rdata)
                except Exception:
                    pass
                ans = ans.payload if hasattr(ans, "payload") else None
                if not isinstance(ans, DNSRR):
                    break
        return ips

    def _alert(self, kind: str, msg: str, colour: str = YELLOW) -> None:
        self.alerts_raised += 1
        log(c(f"[{kind}] {msg}", colour))

    # ── Packet handler ────────────────────────────────────────────────────────

    def handle_packet(self, pkt) -> None:
        self.packets_seen += 1

        if not (pkt.haslayer(DNS) and pkt.haslayer(IP)):
            return

        dns  = pkt[DNS]
        now  = datetime.datetime.now()
        src  = pkt[IP].src
        dst  = pkt[IP].dst
        qid  = dns.id

        # ── DNS Query (QR == 0) ──────────────────────────────────────────────
        if dns.qr == 0 and dns.qdcount > 0:
            self.queries_seen += 1
            try:
                domain = dns.qd.qname.decode("utf-8").rstrip(".")
            except Exception:
                return
            self.pending_queries[qid] = (now, src, domain)
            return

        # ── DNS Response (QR == 1) ───────────────────────────────────────────
        if dns.qr == 1:
            self.responses_seen += 1

            try:
                domain = dns.qd.qname.decode("utf-8").rstrip(".")
            except Exception:
                domain = "unknown"

            # ── Check 3: unexpected source ───────────────────────────────────
            if self.resolver and src != self.resolver:
                self._alert(
                    "UNEXPECTED-SRC",
                    f"Response for '{domain}' from {src} — "
                    f"expected resolver {self.resolver}",
                    RED,
                )

            # ── Check 4: NXDOMAIN rate ───────────────────────────────────────
            if dns.rcode == 3:  # NXDOMAIN
                q = self.nxdomain_counts[src]
                cutoff = now - datetime.timedelta(seconds=60)
                while q and q[0] < cutoff:
                    q.popleft()
                q.append(now)
                if (
                    len(q) >= self.nxdomain_threshold
                    and src not in self.nxdomain_alerted
                ):
                    self.nxdomain_alerted.add(src)
                    self._alert(
                        "HIGH-NXDOMAIN",
                        f"{src} — {len(q)} NXDOMAIN responses in 60s "
                        f"(threshold={self.nxdomain_threshold})",
                        YELLOW,
                    )

            # ── Check 2: multiple responses for same query ID ────────────────
            self.response_sources[qid].append(src)
            if len(self.response_sources[qid]) > 1:
                sources = ", ".join(self.response_sources[qid])
                self._alert(
                    "MULTI-ANSWER",
                    f"Query ID {qid} ('{domain}') received "
                    f"{len(self.response_sources[qid])} responses "
                    f"from: {sources}",
                    RED,
                )

            # ── Check 1: answer mismatch ─────────────────────────────────────
            ips = self._extract_a_records(pkt)
            if not ips:
                return

            self._prune_history(domain, now)
            history = self.answer_history[domain]

            for prev_ts, prev_ips, prev_src in history:
                if prev_ips != ips:
                    age = (now - prev_ts).total_seconds()
                    self._alert(
                        "ANSWER-MISMATCH",
                        f"'{domain}' resolved differently:\n"
                        f"  prev ({age:.0f}s ago, from {prev_src}): {prev_ips}\n"
                        f"  now  (from {src}):                       {ips}",
                        RED,
                    )

            history.append((now, ips, src))

            # ── Check 5: authoritative cross-check ───────────────────────────
            if self.verify and ips:
                auth_ips = authoritative_lookup(domain)
                if auth_ips and not ips.intersection(auth_ips):
                    self._alert(
                        "AUTH-MISMATCH",
                        f"'{domain}' — local answer {ips} does NOT "
                        f"match authoritative answer {auth_ips} "
                        f"(possible local poisoning)",
                        RED,
                    )

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            "",
            c("─── DNS Anomaly Detection Summary ───", BOLD),
            f"  Packets analysed    : {self.packets_seen}",
            f"  Queries seen        : {self.queries_seen}",
            f"  Responses seen      : {self.responses_seen}",
            f"  Alerts raised       : {self.alerts_raised}",
            f"  Unique domains seen : {len(self.answer_history)}",
            f"  High-NXDOMAIN IPs   : {len(self.nxdomain_alerted)}",
        ]
        if self.alerts_raised == 0:
            lines.append(c("  No anomalies detected.", GREEN))
        return "\n".join(lines)


# ── Run modes ─────────────────────────────────────────────────────────────────

def run_live(detector: DnsAnomalyDetector, iface: str) -> None:
    log(c(f"Live capture on interface: {iface}", CYAN))
    if detector.resolver:
        log(f"Trusted resolver: {detector.resolver}")
    log("Press Ctrl+C to stop.\n")
    try:
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=detector.handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(c("ERROR: Permission denied. Run with sudo.", RED))
        sys.exit(1)
    finally:
        print(detector.summary())


def run_pcap(detector: DnsAnomalyDetector, pcap_path: str) -> None:
    p = Path(pcap_path)
    if not p.exists():
        print(c(f"ERROR: File not found: {pcap_path}", RED))
        sys.exit(1)

    log(c(f"Analysing pcap: {pcap_path}", CYAN))
    if detector.resolver:
        log(f"Trusted resolver: {detector.resolver}")
    print()

    count = 0
    with PcapReader(str(p)) as reader:
        for pkt in reader:
            detector.handle_packet(pkt)
            count += 1

    log(f"Finished. {count} total packets in file.")
    print(detector.summary())


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DNS anomaly detector — mismatches, rogue resolvers, high NXDOMAIN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--iface", "-i", metavar="INTERFACE",
                       help="Network interface for live capture (e.g. eth0)")
    group.add_argument("--pcap", "-p", metavar="FILE",
                       help="Read from a saved pcap file")
    parser.add_argument(
        "--resolver", "-r",
        default=None,
        metavar="IP",
        help="Trusted DNS resolver IP (default: auto-detect from /etc/resolv.conf)",
    )
    parser.add_argument(
        "--window", "-w",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Time window for mismatch detection in seconds (default: 60)",
    )
    parser.add_argument(
        "--nxdomain-threshold", "-n",
        type=int,
        default=20,
        metavar="N",
        help="NXDOMAIN responses/min before alerting (default: 20)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Cross-check answers against authoritative DNS (needs dig + internet)",
    )
    parser.add_argument(
        "--log", "-l",
        default=None,
        metavar="FILE",
        help="Append alerts to this log file",
    )
    return parser.parse_args()


def main() -> None:
    global _log_fh

    args     = parse_args()
    resolver = args.resolver or detect_resolver()

    if resolver:
        print(f"Trusted resolver: {resolver}")
    else:
        print(c("WARNING: No resolver detected. Unexpected-source check disabled.", YELLOW))

    if args.log:
        _log_fh = open(args.log, "a")

    detector = DnsAnomalyDetector(
        resolver           = resolver,
        mismatch_window    = args.window,
        nxdomain_threshold = args.nxdomain_threshold,
        verify             = args.verify,
    )

    try:
        if args.iface:
            run_live(detector, args.iface)
        else:
            run_pcap(detector, args.pcap)
    finally:
        if _log_fh:
            _log_fh.close()


if __name__ == "__main__":
    main()
