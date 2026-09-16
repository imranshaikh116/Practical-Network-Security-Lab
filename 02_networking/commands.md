# 02 Command Notebook — Networking: Learn the Wire

This module is about understanding traffic at the packet and protocol level. The offensive angle is to see what is reachable and how the traffic actually behaves. The defensive angle is to understand what normal traffic should look like and what strange behavior indicates tampering.

## 1) Interface and route inspection

```bash
ip -br addr
ip link
ip route
ip route get <TARGET>
ip neigh
```

### Offensive use
- `ip -br addr`: identify the machine’s interfaces and IP addresses.
- `ip route`: show the route table and default gateway.
- `ip route get <TARGET>`: confirm which path a packet will take to a given destination.
- `ip neigh`: inspect the ARP/NDP neighbor table, which matters in MITM and spoofing exercises.

### Defensive use
- These commands are used to validate whether a host is using the correct gateway, expected NICs, and valid local mappings.
- If the route table or neighbor table changes unexpectedly, it may indicate network poisoning, misconfiguration, or a malicious host on the segment.

---

## 2) Connectivity and path testing

```bash
ping -c 4 <TARGET>
tracepath <TARGET>
```

### Offensive use
- `ping`: check if the host responds and whether the network path is live.
- `tracepath`: identify the route path and where packets stop or delay.

### Defensive use
- These commands help confirm whether connectivity is normal or if a service is dropping packets or being redirected.
- Sudden packet loss or path change can be a sign of a network issue or an attacker manipulating traffic.

---

## 3) Socket inspection

```bash
ss -lntup
ss -ant
ss -uan
```

### Offensive use
- `ss -lntup`: show listening TCP sockets and the process owning them.
- `ss -ant`: inspect all TCP sockets and their states.
- `ss -uan`: inspect UDP sockets and listeners.

### Defensive use
- Blue teams rely on these to identify unauthorized listeners, unexpected service ports, and suspicious socket states.
- `TIME_WAIT`, `SYN_RECV`, or high connection counts can indicate abuse, SYN flood, or a misbehaving application.

---

## 4) DNS and name resolution

```bash
dig example.com
dig A example.com
dig MX example.com
dig NS example.com
dig +trace example.com
```

### Offensive use
- `dig` is used to examine DNS answers, server responses, and caching behavior.
- `dig +trace` follows the DNS hierarchy and shows how an answer is resolved.

### Defensive use
- These commands reveal whether a host is using the expected resolver and whether DNS responses are trustworthy.
- Unexpected resolver IPs or suspicious answer records are strong indicators of DNS manipulation.

---

## 5) HTTP request analysis

```bash
curl -I http://<TARGET>/
curl -v http://<TARGET>/
curl -s http://<TARGET>/ | head
```

### Offensive use
- `curl -I`: fetch headers and status code without downloading the whole body.
- `curl -v`: show verbose request/response flow, including connection and TLS negotiation details.
- `curl -s` with `head`: quickly read a small portion of the response for content and behavior checks.

### Defensive use
- Helps confirm whether the service behaves as expected, which headers are exposed, and whether a page is redirecting to an unexpected location.
- A defender can use this to detect misconfigured web services, redirect abuse, or hidden endpoints.

---

## 6) Packet capture and reading traffic

```bash
sudo tcpdump -i any -nn
sudo tcpdump -i any -nn host <TARGET>
sudo tcpdump -i any -nn port 53
sudo tcpdump -i any -nn -w capture.pcap
tcpdump -nn -r capture.pcap
```

### Offensive use
- `tcpdump` captures the exact packets going across the wire.
- This is how you prove what occurred in a lab network instead of guessing.
- `-w` writes to a pcap file; `-r` reads it later for analysis.

### Defensive use
- Blue teams need packet captures to reconstruct an event timeline and verify how traffic moved through the network.
- Packet evidence helps answer: what IPs talked to each other, what ports were used, and what content was visible.

---

## Key offensive/defensive lesson

Offense:
- Map the path
- Check the route and neighbor table
- Validate the port and service
- Inspect the actual traffic

Defense:
- Monitor unusual routes
- Verify expected gateway and DNS settings
- Detect unauthorized listeners
- Preserve packet captures for investigation

The network is not “just a bunch of IPs.” It is a set of trust boundaries and protocol rules that can be abused when a host accepts the wrong signal or wrong peer.
