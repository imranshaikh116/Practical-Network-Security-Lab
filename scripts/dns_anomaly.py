#!/usr/bin/env python3
"""
pcap_summary.py
---------------
Reads a .pcap or .pcapng file and prints a structured, colour-coded
summary covering:

  • Protocol distribution (Ethernet / ARP / IP / TCP / UDP / ICMP / DNS
    / HTTP / TLS / Other)
  • Top talkers by source IP (packet count + byte volume)
  • Top destination IPs
  • Top TCP/UDP port pairs
  • ARP table reconstructed from the capture (IP → MAC bindings)
  • DNS queries and answers seen
  • HTTP requests in cleartext (method, host, path)
  • TLS SNI values (hostnames visible even in encrypted traffic)
  • Suspicious indicators: duplicate ARP bindings, cleartext creds
    patterns, non-standard ports for known protocols

Usage
-----
    python3 pcap_summary.py capture.pcap
    python3 pcap_summary.py capture.pcap --top 20
    python3 pcap_summary.py capture.pcap --out report.txt
    python3 pcap_summary.py capture.pcap --no-colour

Requires
--------
    pip install scapy
    (Pre-installed on Kali Linux.)
    No root required — reads from file only.
"""

import argparse
import collections
import re
import sys
from pathlib import Path
from typing import Optional

try:
    from scapy.all import (
        ARP, DNS, DNSQR, DNSRR,
        Ether, IP, IPv6,
        TCP, UDP, ICMP,
        Raw,
        PcapReader,
        conf as scapy_conf,
    )
    scapy_conf.verb = 0
except ImportError:
    print(
        "ERROR: scapy is not installed.\n"
        "Install it with:  pip install scapy\n"
        "Kali Linux: it is pre-installed."
    )
    sys.exit(1)


# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


USE_COLOUR = True


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}" if USE_COLOUR else text


def header(title: str) -> str:
    bar = "─" * (len(title) + 4)
    return (
        f"\n{c(bar, CYAN)}\n"
        f"  {c(title, BOLD)}\n"
        f"{c(bar, CYAN)}"
    )


# ── Known port → service map (common ones) ────────────────────────────────────

PORT_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp-server", 68: "dhcp-client",
    80: "http", 110: "pop3", 143: "imap", 161: "snmp",
    179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission",
    636: "ldaps", 993: "imaps", 995: "pop3s",
    1194: "openvpn", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch",
}


def port_label(port: int) -> str:
    name = PORT_NAMES.get(port, "")
    return f"{port}/{name}" if name else str(port)


# ── TLS SNI extractor ─────────────────────────────────────────────────────────

def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello and extract the SNI hostname if present.
    Handles TLS 1.0–1.3 ClientHello format.
    """
    try:
        if len(payload) < 5:
            return None
        # Record layer: content type 0x16 = handshake
        if payload[0] != 0x16:
            return None
        # Handshake type 0x01 = ClientHello
        if payload[5] != 0x01:
            return None

        pos = 5 + 4        # skip handshake header
        pos += 2           # skip legacy version
        pos += 32          # skip random
        session_len = payload[pos]; pos += 1 + session_len
        cipher_len  = int.from_bytes(payload[pos:pos+2], "big"); pos += 2 + cipher_len
        comp_len    = payload[pos]; pos += 1 + comp_len

        if pos + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        end = pos + ext_total

        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
            ext_len  = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
            if ext_type == 0:    # SNI extension
                # server_name_list_length (2), server_name_type (1), name_length (2)
                if pos + 5 <= len(payload):
                    name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                    return payload[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
            pos += ext_len

    except (IndexError, ValueError):
        pass

    return None


# ── HTTP request extractor ────────────────────────────────────────────────────

HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT) (\S+) HTTP/[\d.]+\r\n",
    re.MULTILINE,
)
HTTP_HOST_RE = re.compile(rb"^Host:\s*(\S+)", re.MULTILINE | re.IGNORECASE)

# Simple pattern for cleartext credential leakage
CRED_PATTERNS = [
    re.compile(rb"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
    re.compile(rb"(?i)(Authorization:\s*Basic\s+\S+)"),
    re.compile(rb"(?i)(USER\s+\S+\s*\r?\n)"),           # FTP USER command
    re.compile(rb"(?i)(PASS\s+\S+\s*\r?\n)"),           # FTP PASS command
]


# ── Main stats collector ──────────────────────────────────────────────────────

class PcapStats:
    def __init__(self, top_n: int = 15):
        self.top_n = top_n

        # Protocol counts
        self.proto_counts: dict[str, int] = collections.defaultdict(int)

        # Traffic volume
        self.total_packets = 0
        self.total_bytes   = 0

        # Top talkers
        self.src_ip_packets: dict[str, int] = collections.defaultdict(int)
        self.src_ip_bytes:   dict[str, int] = collections.defaultdict(int)
        self.dst_ip_packets: dict[str, int] = collections.defaultdict(int)

        # Port pairs: (proto, src_port, dst_port) → count
        self.port_pairs: dict[tuple, int] = collections.defaultdict(int)

        # ARP table: ip → set of MACs seen
        self.arp_table: dict[str, set] = collections.defaultdict(set)
        # ARP query counts
        self.arp_who_has: dict[str, int] = collections.defaultdict(int)

        # DNS: domain → set of answer IPs
        self.dns_answers:  dict[str, set] = collections.defaultdict(set)
        self.dns_queries:  list[tuple]    = []      # (src_ip, domain)
        self.nxdomain_ips: dict[str, int] = collections.defaultdict(int)

        # HTTP
        self.http_requests: list[tuple] = []    # (src, dst, method, host, path)

        # TLS SNI
        self.tls_sni: list[tuple] = []          # (src, dst, sni)

        # Credential leakage findings
        self.cred_findings: list[str] = []

    # ── Packet processing ─────────────────────────────────────────────────────

    def process(self, pkt) -> None:
        self.total_packets += 1
        pkt_len = len(pkt)
        self.total_bytes += pkt_len

        # ── Ethernet ──────────────────────────────────────────────────────────
        if pkt.haslayer(Ether):
            self.proto_counts["Ethernet"] += 1

        # ── ARP ───────────────────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            self.proto_counts["ARP"] += 1
            if arp.op == 1:   # who-has
                self.arp_who_has[arp.pdst] += 1
            elif arp.op == 2:   # is-at
                self.arp_table[arp.psrc].add(arp.hwsrc.lower())
            return

        # ── IP ────────────────────────────────────────────────────────────────
        if pkt.haslayer(IP):
            ip = pkt[IP]
            self.proto_counts["IP"] += 1
            self.src_ip_packets[ip.src] += 1
            self.src_ip_bytes[ip.src]   += pkt_len
            self.dst_ip_packets[ip.dst] += 1

            # ── ICMP ─────────────────────────────────────────────────────────
            if pkt.haslayer(ICMP):
                self.proto_counts["ICMP"] += 1

            # ── UDP ───────────────────────────────────────────────────────────
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                self.proto_counts["UDP"] += 1
                self.port_pairs[("UDP", udp.sport, udp.dport)] += 1

                # DNS over UDP
                if pkt.haslayer(DNS):
                    self._process_dns(pkt, ip.src)

            # ── TCP ───────────────────────────────────────────────────────────
            elif pkt.haslayer(TCP):
                tcp = pkt[TCP]
                self.proto_counts["TCP"] += 1
                self.port_pairs[("TCP", tcp.sport, tcp.dport)] += 1

                # DNS over TCP
                if pkt.haslayer(DNS):
                    self._process_dns(pkt, ip.src)

                # HTTP / TLS
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    self._process_http(payload, ip.src, ip.dst, tcp.dport)
                    self._process_tls(payload, ip.src, ip.dst)
                    self._process_cred_leak(payload, ip.src, ip.dst, tcp.dport)

        elif pkt.haslayer(IPv6):
            self.proto_counts["IPv6"] += 1
        else:
            self.proto_counts["Other"] += 1

    # ── Sub-processors ────────────────────────────────────────────────────────

    def _process_dns(self, pkt, src_ip: str) -> None:
        dns = pkt[DNS]
        self.proto_counts["DNS"] += 1

        if dns.qr == 0 and dns.qdcount > 0:
            try:
                domain = dns.qd.qname.decode("utf-8").rstrip(".")
                self.dns_queries.append((src_ip, domain))
            except Exception:
                pass

        elif dns.qr == 1:
            try:
                domain = dns.qd.qname.decode("utf-8").rstrip(".")
            except Exception:
                domain = "unknown"

            if dns.rcode == 3:
                self.nxdomain_ips[src_ip] += 1

            ans = dns.an
            while ans:
                try:
                    if ans.type == 1:
                        self.dns_answers[domain].add(ans.rdata)
                except Exception:
                    pass
                ans = ans.payload if hasattr(ans, "payload") else None
                if not isinstance(ans, DNSRR):
                    break

    def _process_http(
        self, payload: bytes, src: str, dst: str, dport: int
    ) -> None:
        matches = HTTP_REQUEST_RE.findall(payload)
        if not matches:
            return
        self.proto_counts["HTTP"] += 1
        host_match = HTTP_HOST_RE.search(payload)
        host = host_match.group(1).decode("utf-8", errors="ignore") if host_match else dst
        for method, path in matches:
            self.http_requests.append((
                src, dst,
                method.decode("utf-8", errors="ignore"),
                host,
                path.decode("utf-8", errors="ignore"),
            ))

    def _process_tls(self, payload: bytes, src: str, dst: str) -> None:
        sni = extract_sni(payload)
        if sni:
            self.proto_counts["TLS"] += 1
            self.tls_sni.append((src, dst, sni))

    def _process_cred_leak(
        self, payload: bytes, src: str, dst: str, dport: int
    ) -> None:
        for pat in CRED_PATTERNS:
            m = pat.search(payload)
            if m:
                preview = m.group(0)[:80].decode("utf-8", errors="ignore")
                service = PORT_NAMES.get(dport, str(dport))
                self.cred_findings.append(
                    f"  {src} → {dst}:{dport} ({service})  |  {preview}"
                )

    # ── Printing ──────────────────────────────────────────────────────────────

    def print_report(self, out=None) -> None:
        lines = []

        def emit(s: str = "") -> None:
            lines.append(s)

        def top(d: dict, n: int, fmt="{k:40s}  {v:>8}") -> None:
            for k, v in sorted(d.items(), key=lambda x: -x[1])[:n]:
                emit("  " + fmt.format(k=str(k), v=v))

        # ── Header ────────────────────────────────────────────────────────────
        emit(header("PCAP SUMMARY"))
        emit(f"  Total packets : {self.total_packets:,}")
        emit(f"  Total bytes   : {self.total_bytes:,}  "
             f"({self.total_bytes / 1024:.1f} KB)")

        # ── Protocol distribution ─────────────────────────────────────────────
        emit(header("Protocol Distribution"))
        for proto, count in sorted(
            self.proto_counts.items(), key=lambda x: -x[1]
        ):
            pct = count / max(self.total_packets, 1) * 100
            bar = "█" * int(pct / 2)
            emit(f"  {proto:15s}  {count:8,}  {pct:5.1f}%  {c(bar, CYAN)}")

        # ── Top source IPs ────────────────────────────────────────────────────
        emit(header(f"Top {self.top_n} Source IPs (packets)"))
        for ip, count in sorted(
            self.src_ip_packets.items(), key=lambda x: -x[1]
        )[:self.top_n]:
            kb = self.src_ip_bytes.get(ip, 0) / 1024
            emit(f"  {ip:20s}  {count:8,} pkts  {kb:8.1f} KB")

        # ── Top destination IPs ───────────────────────────────────────────────
        emit(header(f"Top {self.top_n} Destination IPs (packets)"))
        top(self.dst_ip_packets, self.top_n, fmt="{k:40s}  {v:>8} pkts")

        # ── Top port pairs ────────────────────────────────────────────────────
        emit(header(f"Top {self.top_n} Port Pairs"))
        for (proto, sport, dport), count in sorted(
            self.port_pairs.items(), key=lambda x: -x[1]
        )[:self.top_n]:
            emit(
                f"  {proto:4s}  {port_label(sport):22s} → "
                f"{port_label(dport):22s}  {count:6,}"
            )

        # ── ARP table ─────────────────────────────────────────────────────────
        emit(header("ARP Bindings Observed"))
        if self.arp_table:
            for ip, macs in sorted(self.arp_table.items()):
                mac_str = ", ".join(sorted(macs))
                flag = ""
                if len(macs) > 1:
                    flag = c("  ← MULTIPLE MACs (ARP spoofing?)", RED)
                emit(f"  {ip:20s}  {mac_str}{flag}")
        else:
            emit("  No ARP replies captured.")

        # ── DNS ───────────────────────────────────────────────────────────────
        emit(header("DNS Queries (sample — up to 30)"))
        if self.dns_queries:
            seen: set = set()
            shown = 0
            for src, domain in self.dns_queries:
                if domain not in seen:
                    seen.add(domain)
                    emit(f"  {src:20s}  queried  {domain}")
                    shown += 1
                    if shown >= 30:
                        break
            if len(self.dns_queries) > 30:
                emit(f"  ... and {len(self.dns_queries) - 30} more")
        else:
            emit("  No DNS queries captured.")

        emit(header("DNS Answers (domain → resolved IPs)"))
        if self.dns_answers:
            for domain, ips in sorted(self.dns_answers.items()):
                flag = c("  ← multiple answers", YELLOW) if len(ips) > 1 else ""
                emit(f"  {domain:40s}  {', '.join(sorted(ips))}{flag}")
        else:
            emit("  No DNS answers captured.")

        if self.nxdomain_ips:
            emit(header("High NXDOMAIN Sources"))
            for ip, count in sorted(
                self.nxdomain_ips.items(), key=lambda x: -x[1]
            )[:self.top_n]:
                emit(f"  {ip:20s}  {count:5,} NXDOMAINs")

        # ── HTTP ──────────────────────────────────────────────────────────────
        emit(header(f"HTTP Requests (cleartext) — up to {self.top_n}"))
        if self.http_requests:
            for src, dst, method, host, path in self.http_requests[:self.top_n]:
                emit(f"  {src:18s} → {host}  {c(method, YELLOW)} {path[:80]}")
            if len(self.http_requests) > self.top_n:
                emit(f"  ... and {len(self.http_requests) - self.top_n} more")
        else:
            emit("  No cleartext HTTP requests found.")

        # ── TLS SNI ───────────────────────────────────────────────────────────
        emit(header(f"TLS SNI Values (hostnames in encrypted traffic) — up to {self.top_n}"))
        if self.tls_sni:
            seen_sni: set = set()
            count = 0
            for src, dst, sni in self.tls_sni:
                if sni not in seen_sni:
                    seen_sni.add(sni)
                    emit(f"  {src:18s} → {dst:18s}  SNI={c(sni, CYAN)}")
                    count += 1
                    if count >= self.top_n:
                        break
        else:
            emit("  No TLS ClientHello packets found.")

        # ── Credential leakage ────────────────────────────────────────────────
        emit(header("Potential Cleartext Credential Patterns"))
        if self.cred_findings:
            for f in self.cred_findings[:20]:
                emit(c(f, RED))
            if len(self.cred_findings) > 20:
                emit(f"  ... and {len(self.cred_findings) - 20} more")
        else:
            emit(c("  None detected.", GREEN))

        # ── Suspicious ARP duplicates ─────────────────────────────────────────
        dup_ips = [ip for ip, macs in self.arp_table.items() if len(macs) > 1]
        if dup_ips:
            emit(header("SUSPICIOUS — IPs with Multiple MAC Bindings"))
            for ip in dup_ips:
                macs = sorted(self.arp_table[ip])
                emit(c(f"  {ip}  →  {', '.join(macs)}", RED))

        emit("")

        # ── Output ────────────────────────────────────────────────────────────
        full_text = "\n".join(lines)
        print(full_text)

        if out:
            # Strip ANSI when writing to file
            ansi_escape = re.compile(r"\033\[[0-9;]*m")
            clean = ansi_escape.sub("", full_text)
            Path(out).write_text(clean)
            print(c(f"\nReport saved to: {out}", GREEN))


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="pcap_summary — protocol stats, top talkers, ARP table, DNS, HTTP, TLS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("pcap", metavar="FILE", help="Path to .pcap or .pcapng file")
    parser.add_argument("--top", "-n", type=int, default=15, metavar="N",
                        help="Number of top entries to show (default: 15)")
    parser.add_argument("--out", "-o", default=None, metavar="FILE",
                        help="Save plain-text report to this file")
    parser.add_argument("--no-colour", action="store_true",
                        help="Disable ANSI colour output")
    return parser.parse_args()


def main() -> None:
    global USE_COLOUR

    args = parse_args()
    if args.no_colour or not sys.stdout.isatty():
        USE_COLOUR = False

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(c(f"ERROR: File not found: {args.pcap}", RED))
        sys.exit(1)

    stats = PcapStats(top_n=args.top)

    print(c(f"Reading: {args.pcap}", CYAN))
    count = 0
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            stats.process(pkt)
            count += 1
            if count % 10_000 == 0:
                print(f"  ... {count:,} packets processed", end="\r")

    print(f"  {count:,} packets total.{' ' * 20}")
    stats.print_report(out=args.out)


if __name__ == "__main__":
    main()
