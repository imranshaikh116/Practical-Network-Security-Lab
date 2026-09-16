#!/usr/bin/env python3
"""Summarize packet captures and print per-protocol statistics.

This is intended for lab analysis and network forensics. It will try to use
Scapy if installed; otherwise it prints a helpful install message.
"""

import argparse
import sys
from collections import Counter


try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP
except ImportError:  # pragma: no cover
    PcapReader = None


def summarize_pcap(path):
    if PcapReader is None:
        raise RuntimeError("Scapy is not installed. Run: pip install scapy")

    total_packets = 0
    protocol_counts = Counter()
    src_ips = Counter()
    dst_ips = Counter()

    with PcapReader(path) as pcap:
        for pkt in pcap:
            total_packets += 1

            if ARP in pkt:
                protocol_counts["ARP"] += 1
            elif IPv6 in pkt:
                protocol_counts["IPv6"] += 1
            elif IP in pkt:
                proto = pkt[IP].proto
                if proto == 6:
                    protocol_counts["TCP"] += 1
                elif proto == 17:
                    protocol_counts["UDP"] += 1
                elif proto == 1:
                    protocol_counts["ICMP"] += 1
                else:
                    protocol_counts[f"IP_PROTO_{proto}"] += 1

                src_ips[str(pkt[IP].src)] += 1
                dst_ips[str(pkt[IP].dst)] += 1
            elif IPv6 in pkt:
                src_ips[str(pkt[IPv6].src)] += 1
                dst_ips[str(pkt[IPv6].dst)] += 1
            else:
                protocol_counts["OTHER"] += 1

    return {
        "total_packets": total_packets,
        "protocol_counts": protocol_counts,
        "src_ips": src_ips,
        "dst_ips": dst_ips,
    }


def print_summary(summary):
    print(f"[+] Total packets: {summary['total_packets']}")
    print("[+] Protocol breakdown:")
    for proto, count in summary["protocol_counts"].most_common():
        print(f"    {proto}: {count}")

    print("\n[+] Top source IPs:")
    for ip, count in summary["src_ips"].most_common(5):
        print(f"    {ip}: {count}")

    print("\n[+] Top destination IPs:")
    for ip, count in summary["dst_ips"].most_common(5):
        print(f"    {ip}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Print a packet-level summary for a .pcap file.")
    parser.add_argument("pcap", help="Path to the .pcap file to summarize")
    args = parser.parse_args()

    try:
        summary = summarize_pcap(args.pcap)
        print_summary(summary)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.pcap}")
        sys.exit(1)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)
    except Exception as exc:  # pragma: no cover
        print(f"[ERROR] Failed to parse PCAP: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
