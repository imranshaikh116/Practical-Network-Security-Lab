# 06 Command Notebook — DNS: Resolution, Cache, and Trust

DNS is not just a lookup system. It is part of the trust chain between a client and the network. The offensive angle is to understand who the client trusts, how the answer is cached, and whether a malicious resolver or spoofed answer could redirect traffic. The defensive angle is to validate the resolver chain, inspect abnormal DNS behavior, and detect unexpected record changes.

## 1) Query types and record inspection

```bash
dig A lab.test
dig NS lab.test
dig MX lab.test
dig TXT lab.test
dig @192.168.56.30 web.lab.test
dig +dnssec example.com
```

### Offensive purpose
- `dig A`: query the address record for a name.
- `dig NS`, `dig MX`, `dig TXT`: inspect the zone metadata and service record types.
- `dig @192.168.56.30 web.lab.test`: query a specific lab DNS server to test controlled zone behavior.
- `dig +dnssec`: request DNSSEC records to study record authentication.

### Defensive purpose
- Blue teams use these commands to verify that a client is using the correct resolver and that records match expected values.
- Unexpected A/NS/MX responses or suspicious TXT data can be signs of poisoning or misconfiguration.

---

## 2) Resolver configuration and trust path

```bash
resolvectl status
cat /etc/resolv.conf
```

### Offensive purpose
- These commands reveal which DNS server the host is configured to use.
- Attackers can detect whether a host is using a rogue or untrusted resolver.

### Defensive purpose
- Defenders use them to confirm the client is using approved internal resolvers and not a malicious external DNS service.

---

## 3) Packet capture for DNS traffic

```bash
sudo tcpdump -i any -nn port 53
sudo tcpdump -i any -nn -w dns.pcap port 53
tcpdump -nn -r dns.pcap
```

### Offensive purpose
- `tcpdump port 53` captures DNS queries and responses.
- This lets you see the actual request/response exchange and validate whether the resolver or server is giving the expected answer.
- `dns.pcap` preserves evidence for later review.

### Defensive purpose
- DNS traffic capture is critical for incident response and detection engineering.
- A defender wants to know: which host queried suspicious domains, which resolver answered, and whether the response matched the expected server or cached answer.

---

## Defensive controls to validate

- Approved internal resolvers only
- DNSSEC validation
- Monitoring for short TTLs or unexpected record changes
- Detection of external DNS clients bypassing approved resolvers
- Logging of high-volume NXDOMAIN or suspicious domain lookups

### Key lesson
- DNS is not only name resolution; it is trust in the answer.
- If the resolver or client accepts a false answer, it can redirect traffic silently.
