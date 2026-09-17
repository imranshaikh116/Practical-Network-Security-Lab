# Detection Scripts

Four standalone Python 3 detection tools for the lab.
No third-party packages except **scapy** (pre-installed on Kali Linux).

---

## Install dependencies

```bash
pip install scapy
```

On Kali Linux scapy is already present — no install needed.

---

## Scripts

### `arp_monitor.py` — Live ARP / MITM detector

Polls `ip neigh` every N seconds and alerts the moment any IP's MAC address changes — the primary signature of ARP spoofing.

```bash
# Basic run (poll every 5s)
sudo python3 arp_monitor.py

# Poll every 2s, restrict to eth0, log alerts to file
sudo python3 arp_monitor.py --interval 2 --iface eth0 --log arp.log

# Pre-load a whitelist of trusted IP→MAC pairs
sudo python3 arp_monitor.py --whitelist whitelist.txt
```

**Whitelist format** (`whitelist.txt`):
```
192.168.56.1  aa:bb:cc:dd:ee:ff
192.168.56.20 11:22:33:44:55:66
```

**What it detects:** gratuitous ARP replies, MAC binding changes, locally-administered MAC addresses.

---

### `ssh_bruteforce_detect.py` — SSH brute-force detector

Parses `/var/log/auth.log` and groups failed SSH logins by source IP within a sliding time window. Raises an alert when the threshold is crossed, and a critical alert when the same IP then succeeds — the brute-force-to-compromise pattern.

```bash
# Parse default log with defaults (10 failures / 5 min window)
python3 ssh_bruteforce_detect.py

# Custom threshold and window
python3 ssh_bruteforce_detect.py --threshold 5 --window 60

# Follow live (like tail -f)
sudo python3 ssh_bruteforce_detect.py --tail

# Write a findings report
python3 ssh_bruteforce_detect.py --report ssh_findings.txt
```

**Alert levels:**
- `[BRUTE-FORCE]` — IP crossed failure threshold
- `[COMPROMISE ]` — same IP logged in successfully after brute-force alert

---

### `dns_anomaly.py` — DNS anomaly detector

Monitors DNS traffic (live capture or saved pcap) for:

| Alert | Meaning |
|---|---|
| `ANSWER-MISMATCH` | Same domain returns different IPs within the time window |
| `MULTI-ANSWER` | Single query gets >1 response packet (race injection) |
| `UNEXPECTED-SRC` | Answer from an IP that isn't your configured resolver |
| `HIGH-NXDOMAIN` | Unusual rate of NXDOMAIN from one source |
| `AUTH-MISMATCH` | Local answer doesn't match authoritative (with `--verify`) |

```bash
# Live capture on eth0
sudo python3 dns_anomaly.py --iface eth0

# Analyse a saved pcap
python3 dns_anomaly.py --pcap capture.pcap

# Specify trusted resolver explicitly
sudo python3 dns_anomaly.py --iface eth0 --resolver 192.168.56.30

# Cross-check answers against authoritative DNS
sudo python3 dns_anomaly.py --iface eth0 --verify

# Log alerts to file
sudo python3 dns_anomaly.py --iface eth0 --log dns_alerts.log
```

---

### `pcap_summary.py` — PCAP forensic summariser

Reads any `.pcap` / `.pcapng` file and prints a structured report:

- Protocol distribution with percentages
- Top talkers by packet count and byte volume
- Top destination IPs
- Top TCP/UDP port pairs (with service names)
- ARP table reconstructed from the capture (flags duplicate MACs)
- DNS queries and resolved answers
- Cleartext HTTP requests (method, host, path)
- TLS SNI values (hostnames visible even in encrypted sessions)
- Cleartext credential patterns (Basic Auth, FTP USER/PASS, password= params)

```bash
# Basic summary
python3 pcap_summary.py capture.pcap

# Show top 25 entries instead of 15
python3 pcap_summary.py capture.pcap --top 25

# Save plain-text report
python3 pcap_summary.py capture.pcap --out report.txt

# No colour (for piping)
python3 pcap_summary.py capture.pcap --no-colour
```

---

## Suggested lab workflow

```
1. Start arp_monitor.py on the defender VM BEFORE any MITM exercise
2. Run tcpdump -w capture.pcap on a separate terminal
3. Execute the Module 5 / 6 / 8 lab
4. Stop tcpdump, run pcap_summary.py on the capture
5. Check dns_anomaly.py output if DNS exercises were involved
6. After SSH exercises, run ssh_bruteforce_detect.py against auth.log
7. Compare all findings — do they match what you did as the attacker?
```

This mirrors the real SOC workflow: generate the event, detect it from logs, correlate across tools.

---

## Output example — pcap_summary.py

```
──────────────────────────────
  Protocol Distribution
──────────────────────────────
  Ethernet         1024     100.0%
  IP               1001      97.8%
  TCP               880      85.9%
  DNS               120      11.7%
  HTTP               64       6.3%
  TLS                56       5.5%
  ARP                23       2.2%

──────────────────────────────
  ARP Bindings Observed
──────────────────────────────
  192.168.56.1    aa:bb:cc:dd:ee:ff
  192.168.56.20   11:22:33:44:55:66, de:ad:be:ef:00:01  ← MULTIPLE MACs (ARP spoofing?)
```

---

## Safety reminder

Run these scripts only against traffic and log files from your own isolated lab network.
