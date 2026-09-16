# Lab Scripts

This folder contains small, lab-friendly Python utilities for monitoring, detecting, and summarizing network activity in a controlled VM environment.

These scripts are intended for educational and defensive analysis use in a lab network. Use them only in environments you own or are explicitly authorized to test.

## Scripts

### 1) arp_monitor.py
Purpose:
- monitors neighbor table changes
- identifies ARP/MAC drift
- helps detect spoofing or MITM-style behavior

Usage:
```bash
python scripts/arp_monitor.py --interval 3
```

Example output:
```text
[+] Starting ARP monitor. Press Ctrl+C to stop.
[ALERT] IP 192.168.56.10 changed from 00:11:22:33:44:55 to 00:aa:bb:cc:dd:ee
```

What it proves:
- a host recently changed its MAC address
- a device may have been spoofed or replaced
- a trust boundary is being abused at layer 2

---

### 2) ssh_bruteforce_detect.py
Purpose:
- scans SSH logs for repeated failed authentication attempts
- highlights a likely brute-force pattern
- helps trigger defensive investigation

Usage:
```bash
python scripts/ssh_bruteforce_detect.py /var/log/auth.log --threshold 5 --window 60
```

Example output:
```text
[ALERT] SSH brute-force activity detected:
  - IP 10.0.0.15: 7 failed attempts in 60 seconds
```

What it proves:
- repeated credential guessing is happening
- a source may be attacking SSH access
- log analysis can support detection and blocking decisions

---

### 3) dns_anomaly.py
Purpose:
- detects multiple answers for the same DNS query
- highlights possible DNS spoofing or cache poisoning behavior
- supports analysis of suspicious DNS responses

Usage:
```bash
python scripts/dns_anomaly.py dns_records.txt
```

Example input:
```text
google.com IN A 1.1.1.1
google.com IN A 8.8.8.8
```

Example output:
```text
[ALERT] DNS anomalies detected:
  - Query: google.com (A)
    Answers: 1.1.1.1, 8.8.8.8
```

What it proves:
- the same DNS name resolved to conflicting answers
- a malicious or poisoned resolver may be active
- trust assumptions in domain resolution are being abused

---

### 4) pcap_summary.py
Purpose:
- reads a .pcap file
- summarizes protocol distribution
- shows top source and destination IPs
- helps triage network activity quickly

Usage:
```bash
python scripts/pcap_summary.py capture.pcap
```

Example output:
```text
[+] Total packets: 15420
[+] Protocol breakdown:
    TCP: 9800
    UDP: 4200
    ICMP: 210
    ARP: 210

[+] Top source IPs:
    192.168.56.10: 5400
    192.168.56.20: 4100
```

What it proves:
- which protocols dominate the traffic
- what hosts are most active
- where anomalies or unusual communication may be occurring

---

## General usage notes

- Run scripts against your own lab environment only.
- Store command output as evidence in your workbook or final report.
- Pair each script with a clear note:
  - what the script shows
  - why it matters
  - what control or detection should respond

## Suggested workflow

1. Capture evidence using tcpdump or a lab packet source
2. run the relevant script against the artifact
3. compare findings to expected baseline behavior
4. record the result in your evidence log or report

## Security note

These tools are designed for controlled educational use. They are not a substitute for real production monitoring, intrusion detection, or forensic tooling in a live environment.
