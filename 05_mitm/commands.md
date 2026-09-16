# 05 Command Notebook — MITM and ARP Poisoning

This module is about placing yourself between two hosts and influencing the traffic path. The offensive angle is to manipulate ARP so the victim sends traffic to the attacker. The defensive angle is to detect unexpected ARP mappings and prevent a host from becoming an unauthorized relay.

## 1) Enable forwarding for a relay path

```bash
cat /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.ip_forward=0
```

### Offensive purpose
- `net.ipv4.ip_forward=1` allows the attacking machine to relay traffic rather than just intercept it.
- Without forwarding, you may poison ARP but break the connection path.

### Defensive purpose
- Blue teams check whether IP forwarding is enabled unexpectedly on a host.
- An unexpected relay host on a local segment can become a silent interception point.

---

## 2) Inspect neighbor tables and ARP traffic

```bash
ip neigh
sudo tcpdump -i any -nn arp
```

### Offensive purpose
- `ip neigh` reveals which MAC address owns a given IP.
- `tcpdump arp` shows the ARP traffic used to poison or repair the mapping.

### Defensive purpose
- These commands help defenders catch changes to the local network’s trust mapping.
- If a gateway address is suddenly mapped to an unexpected MAC, that is a major signal.

---

## 3) Poison ARP in a lab-only environment

```bash
sudo arpspoof -i eth0 -t <CLIENT> <GATEWAY>
sudo arpspoof -i eth0 -t <GATEWAY> <CLIENT>
```

### Offensive purpose
- The first command tells the client that the attacker is the gateway.
- The second command tells the gateway that the attacker is the client.
- This creates a two-sided ARP cache poisoning path.

### Defensive purpose
- Defenders look for repeated ARP updates, sudden MAC flips, and abnormal traffic that changes the path between hosts.
- Port security, DHCP snooping, and switch protections reduce the chance of this succeeding.

### Lab safety
- Only do this in an isolated network.
- Always disable forwarding and clear neighbor entries after the lab.

---

## 4) Observe the traffic that crosses the attacker

```bash
sudo tcpdump -i eth0 -nn -A tcp port 80
```

### Offensive purpose
- Capture plaintext HTTP requests and responses to demonstrate what is visible on the network when protocols are unencrypted.

### Defensive purpose
- This helps explain why TLS and safe network controls matter.
- A defender should ask: are there plaintext protocols where confidentiality should exist?

---

## 5) Cleanup

```bash
sudo pkill arpspoof 2>/dev/null || true
sudo sysctl -w net.ipv4.ip_forward=0
sudo ip neigh flush all
```

### Why cleanup matters
- Leaving forwarding enabled or stale ARP entries can sabotage the rest of the lab.
- Clean teardown is part of good security work and evidence preservation.

---

## Key takeaway
- MITM is not just packet capture; it is network-path manipulation.
- The attack works because a host trusts an ARP mapping that can be changed locally.
- The defense is to make unexpected local path changes visible and difficult to achieve.
