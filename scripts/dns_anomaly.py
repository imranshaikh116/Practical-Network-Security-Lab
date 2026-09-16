#!/usr/bin/env python3
"""Identify suspicious DNS behavior when the same query resolves to multiple answers.

This can be useful for spotting DNS spoofing, malicious redirection, or cache abuse.
It reads a text file where each line contains a DNS query and answer, such as:

    google.com A 1.1.1.1
    google.com A 8.8.8.8

You can also feed lines from dig output or custom DNS log formats.
"""

import argparse
import re
from collections import defaultdict


QUERY_RE = re.compile(r"(?P<qname>\S+)\s+(?:IN\s+)?(?P<rtype>[A-Z0-9]+)\s+(?P<answer>\S+)")


def parse_dns_lines(lines):
    records = defaultdict(set)

    for line in lines:
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue

        m = QUERY_RE.search(clean)
        if not m:
            # Allow a second rough pattern for logs like: query google.com IN A -> 1.1.1.1
            alt = re.search(r"(?:query|ANSWER)\s+(?P<qname>\S+)\s+(?:IN\s+)?(?P<rtype>[A-Z0-9]+)\s*(?:->|:|=)?\s*(?P<answer>\S+)", clean, re.I)
            if not alt:
                continue
            qname = alt.group("qname")
            rtype = alt.group("rtype")
            answer = alt.group("answer")
        else:
            qname = m.group("qname")
            rtype = m.group("rtype")
            answer = m.group("answer")

        records[(qname.lower(), rtype.upper())].add(answer)

    return records


def find_anomalies(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        records = parse_dns_lines(handle)

    anomalies = []
    for (qname, rtype), answers in sorted(records.items()):
        if len(answers) > 1:
            anomalies.append({
                "query": qname,
                "type": rtype,
                "answers": sorted(answers),
                "count": len(answers),
            })

    return anomalies


def main():
    parser = argparse.ArgumentParser(description="Flag suspicious DNS answers for the same query.")
    parser.add_argument("path", help="Text file containing DNS records to analyze")
    args = parser.parse_args()

    try:
        anomalies = find_anomalies(args.path)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.path}")
        return

    if not anomalies:
        print("[+] No DNS anomalies detected: each query resolves to a single answer.")
        return

    print("[ALERT] DNS anomalies detected:")
    for item in anomalies:
        print(f"  - Query: {item['query']} ({item['type']})")
        print(f"    Answers: {', '.join(item['answers'])}")


if __name__ == "__main__":
    main()
