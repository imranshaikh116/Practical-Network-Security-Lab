# Sample PCAP Files

Eleven synthetic packet captures for practice, tool testing, and learning to read traffic without needing a live network.

All files use standard libpcap format and open in **Wireshark**, **tcpdump**, and the included [`pcap_summary.py`](../scripts/pcap_summary.py) script.

---

## How to read any file

```bash
# Quick summary in terminal
tcpdump -nn -r samples/01_arp_traffic_sample.pcap

# Full analysis with the included script
python3 scripts/pcap_summary.py samples/01_arp_traffic_sample.pcap

# Open in Wireshark
wireshark samples/01_arp_traffic_sample.pcap &
```

---

## File reference

### `01_arp_traffic_sample.pcap`
**Protocol:** ARP | **Related module:** [02_networking](../02_networking/), [05_mitm](../05_mitm/)

Contains ARP who-has requests, is-at replies, and gratuitous ARP packets across a simulated `/24` subnet.

What to look for:
- The MAC address that responds to each IP
- Any IP that appears with more than one MAC (spoofing indicator)
- Gratuitous ARP packets (unsolicited is-at — normal for GARP, suspicious in bursts)

```bash
tcpdump -nn -r samples/01_arp_traffic_sample.pcap arp
python3 scripts/arp_monitor.py  # run live to detect the same pattern
```

---

### `02_dns_lookup_sample.pcap`
**Protocol:** DNS (UDP 53) | **Related module:** [06_dns](../06_dns/)

A full DNS resolution sequence including A, MX, and NS record queries with responses, TTL values, and a NXDOMAIN response.

What to look for:
- The query transaction ID (16-bit — why it's a weak trust anchor)
- TTL values on each answer
- The difference between a recursive and an authoritative answer
- The NXDOMAIN response and what triggers it

```bash
tcpdump -nn -r samples/02_dns_lookup_sample.pcap port 53
python3 scripts/dns_anomaly.py --pcap samples/02_dns_lookup_sample.pcap
```

---

### `03_tcp_handshake_sample.pcap`
**Protocol:** TCP | **Related module:** [02_networking](../02_networking/), [03_dos](../03_dos/)

A complete TCP session: SYN → SYN/ACK → ACK (handshake), data exchange, and FIN/ACK teardown.

What to look for:
- Sequence and acknowledgement numbers incrementing
- The three-way handshake completing before any data is sent
- Window size negotiation
- How a clean FIN/ACK teardown looks vs an abrupt RST

```bash
tcpdump -nn -r samples/03_tcp_handshake_sample.pcap tcp
tcpdump -nn -r samples/03_tcp_handshake_sample.pcap 'tcp[tcpflags] & tcp-syn != 0'
```

---

### `04_udp_query_sample.pcap`
**Protocol:** UDP | **Related module:** [02_networking](../02_networking/)

Connectionless UDP query/response pairs showing the absence of a handshake and how state must be tracked at the application layer.

What to look for:
- No SYN/ACK — responses are inferred by port matching alone
- How source-port randomisation works as a weak trust signal
- Why UDP is preferred for spoofing attacks (no handshake = no source verification)

```bash
tcpdump -nn -r samples/04_udp_query_sample.pcap udp
```

---

### `05_icmp_echo_sample.pcap`
**Protocol:** ICMP | **Related module:** [02_networking](../02_networking/), [03_dos](../03_dos/)

ICMP echo request/reply sequences (ping), showing TTL values, sequence numbers, and response timing.

What to look for:
- TTL value on the request vs the reply (OS fingerprinting starting point)
- ICMP sequence numbers incrementing
- Round-trip time implied by packet timestamps

```bash
tcpdump -nn -r samples/05_icmp_echo_sample.pcap icmp
```

---

### `06_http_get_sample.pcap`
**Protocol:** HTTP (TCP 80) | **Related module:** [11_web_exploitation](../11_web_exploitation/)

A cleartext HTTP GET request and server response including headers, status code, and response body — fully readable without decryption.

What to look for:
- The full request line (method, path, HTTP version)
- Host, User-Agent, Cookie headers — all cleartext, all capturable by any on-path observer
- The response status and Content-Type
- Why this is the entire argument for HTTPS

```bash
tcpdump -nn -r samples/06_http_get_sample.pcap -A tcp port 80
python3 scripts/pcap_summary.py samples/06_http_get_sample.pcap
```

---

### `07_tls_client_hello_sample.pcap`
**Protocol:** TLS (TCP 443) | **Related module:** [10_crypto](../10_crypto/)

A TLS ClientHello packet showing the SNI extension, supported cipher suites, and TLS version negotiation — the metadata visible even in encrypted sessions.

What to look for:
- The SNI field (hostname in cleartext even under TLS 1.2)
- Cipher suites listed — any `NULL`, `RC4`, `EXPORT`, or `DES` entries are findings
- Supported TLS versions advertised by the client
- What the `pcap_summary.py` script extracts from this automatically

```bash
tcpdump -nn -r samples/07_tls_client_hello_sample.pcap tcp port 443
python3 scripts/pcap_summary.py samples/07_tls_client_hello_sample.pcap
```

---

### `08_broadcast_traffic_sample.pcap`
**Protocol:** L2/L3 broadcast | **Related module:** [02_networking](../02_networking/), [08_dhcp](../08_dhcp/)

Ethernet broadcast and multicast frames including ARP broadcasts and DHCP discovery packets.

What to look for:
- Destination MAC `ff:ff:ff:ff:ff:ff` — how broadcasts reach every host on the segment
- Why broadcast-heavy traffic is a signal of scanning or misconfiguration
- DHCP Discover broadcast — and why any host on the segment can answer it

```bash
tcpdump -nn -r samples/08_broadcast_traffic_sample.pcap ether broadcast
tcpdump -nn -r samples/08_broadcast_traffic_sample.pcap 'udp port 67 or udp port 68'
```

---

### `09_smtp_activity_sample.pcap`
**Protocol:** SMTP (TCP 25) | **Related module:** [07_protocols](../07_protocols/)

An SMTP session showing EHLO, MAIL FROM, RCPT TO, DATA, and a Base64-encoded AUTH LOGIN sequence — credentials visible in cleartext.

What to look for:
- The AUTH LOGIN sequence and its Base64 encoding (not encryption — trivially reversible)
- Why SMTP on port 25 without STARTTLS is equivalent to HTTP for credential exposure
- The difference between SMTP (25), submission (587), and SMTPS (465)

```bash
tcpdump -nn -r samples/09_smtp_activity_sample.pcap -A tcp port 25
python3 scripts/pcap_summary.py samples/09_smtp_activity_sample.pcap
```

---

### `10_port_scan_sample.pcap`
**Protocol:** TCP | **Related module:** [01_foundations](../01_foundations/), [09_router](../09_router/)

A TCP connect scan pattern: SYN probes to sequential ports, RST responses from closed ports, no responses from filtered ports.

What to look for:
- The pattern of SYN → RST/ACK on closed ports (vs SYN → SYN/ACK on open ones)
- Filtered ports showing no response at all
- How scan traffic looks from the target's perspective (what your IDS would see)
- Source port and timing patterns that distinguish a scan from normal traffic

```bash
tcpdump -nn -r samples/10_port_scan_sample.pcap 'tcp[tcpflags] & tcp-syn != 0'
tcpdump -nn -r samples/10_port_scan_sample.pcap 'tcp[tcpflags] & tcp-rst != 0'
```

---

### `11_rogue_dns_response_sample.pcap`
**Protocol:** DNS (UDP 53) | **Related module:** [06_dns](../06_dns/)

A simulated DNS race: a legitimate query followed by two competing responses — one from the real resolver and one forged — with different answer IPs for the same domain.

What to look for:
- Two DNS response packets for a single query ID
- Different answer IPs in each response
- The transaction ID that both responses match
- Why whichever response arrives first wins (and how DNSSEC prevents this)
- The exact pattern the `dns_anomaly.py` script flags as `ANSWER-MISMATCH` and `MULTI-ANSWER`

```bash
tcpdump -nn -r samples/11_rogue_dns_response_sample.pcap port 53
python3 scripts/dns_anomaly.py --pcap samples/11_rogue_dns_response_sample.pcap
```

---

## Using with the detection scripts

```bash
# Full analysis of any sample
python3 scripts/pcap_summary.py samples/<file>.pcap --top 20

# DNS-specific analysis
python3 scripts/dns_anomaly.py --pcap samples/02_dns_lookup_sample.pcap
python3 scripts/dns_anomaly.py --pcap samples/11_rogue_dns_response_sample.pcap

# Save a report
python3 scripts/pcap_summary.py samples/06_http_get_sample.pcap --out report.txt
```

---

## Wireshark filter reference

```
arp                          # only ARP frames
dns                          # only DNS
tcp.flags.syn == 1           # SYN packets
tcp.flags.rst == 1           # RST packets
http                         # cleartext HTTP
tls.handshake.type == 1      # TLS ClientHello (SNI visible here)
udp.port == 67 || udp.port == 68   # DHCP
smtp                         # SMTP traffic
```

---

## Generating your own captures

In your lab VM:

```bash
# Capture all traffic on eth0 for 60 seconds
sudo tcpdump -i eth0 -nn -w my_capture.pcap

# Capture only DNS
sudo tcpdump -i eth0 -nn port 53 -w dns_capture.pcap

# Capture and read immediately
sudo tcpdump -i eth0 -nn -w - | tcpdump -nn -r -
```
