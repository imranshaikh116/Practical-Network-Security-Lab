# 05 — MITM: ARP Poisoning, Traffic Interception, and Network Path Control

## Concept first: interception depends on being in the path

A man-in-the-middle attack is not just passive listening. It is the ability to position yourself between two parties so traffic flows through your machine. On a local network, ARP spoofing is the classic way to do this because clients trust ARP to map IPs to MAC addresses.

### Offensive angle

An attacker poisons the ARP cache so the victim sends frames to the attacker's MAC instead of the legitimate gateway. Once in the forwarding path, the attacker can observe plaintext or manipulate requests if the protocol is weak. The key is to preserve the connection while controlling the flow.

### Defensive angle

Defenders reduce this risk with ARP inspection, switch port security, DHCP snooping, VLAN segmentation, and active monitoring for unexpected MAC changes. The goal is to prevent the attacker from becoming a trusted relay on the network.

### Commands explained

- `ip neigh`: examine the current neighbor table that maps IP addresses to MAC addresses.
- `sysctl -w net.ipv4.ip_forward=1`: enable forwarding so traffic can continue through the attacker.
- `arpspoof`: poison ARP entries between client and gateway.
- `tcpdump -A`: capture raw traffic content, including HTTP requests if the service is not protected.
- `ip neigh flush all`: remove stale entries after the lab.

A real MITM is only meaningful when you can prove you were transparently placed in the path and collected or modified the traffic without breaking the service unexpectedly.

# Read this before touching the lab

Everything in this course is meant for machines you own and a network you deliberately isolated for testing.

Use a Host-Only/Internal network. A simple setup is:

- Kali: `192.168.56.10`
- Target: `192.168.56.20`
- Router: `192.168.56.1`
- Server/DNS/DHCP: `192.168.56.30`

Take VM snapshots before vulnerable configurations.

For attack exercises, replace placeholders such as `<TARGET>` with a lab IP. Do not replace them with a public IP, home router, college network, office network, or someone else's machine.

The point of the lab is not to collect a pile of payloads. For every technique, answer four questions:

1. What is happening on the wire?
2. Why does the target accept it?
3. What evidence would a defender see?
4. What change makes the attack fail?

## Start with the normal path

You want a picture of normal traffic before introducing an attacker.

On the client:

```bash
ip route
ip neigh
```

On the gateway/router:

```bash
ip neigh
```

Capture normal traffic:

```bash
sudo tcpdump -i any -nn -w ~/lab/05_before.pcap host <CLIENT> or host <GATEWAY>
```

Generate a ping and an HTTP request.

## ARP poisoning in the lab

The idea is simple:

```text
Normal:
Client → Gateway MAC

Poisoned:
Client → Attacker MAC
Gateway → Attacker MAC
```

That puts the attacker in the forwarding path.

Enable forwarding temporarily:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
cat /proc/sys/net/ipv4/ip_forward
```

Use a purpose-built lab tool such as `arpspoof` between two of your VMs:

```bash
sudo arpspoof -i eth0 -t <CLIENT> <GATEWAY>
```

and in the other direction:

```bash
sudo arpspoof -i eth0 -t <GATEWAY> <CLIENT>
```

Capture the result:

```bash
sudo tcpdump -i eth0 -nn arp
```

Watch the client's ARP table:

```bash
ip neigh
```

## Why forwarding matters

Without forwarding, you may redirect traffic but break connectivity.

With forwarding enabled, the attacker VM behaves like a relay.

That is an important red-team lesson: interception is not useful if your traffic manipulation destroys the path you are trying to study.

## Observe plaintext HTTP

If your lab web server uses HTTP:

```bash
sudo tcpdump -i eth0 -nn -A tcp port 80
```

Visit the lab site from the client.

You should be able to see application data that is actually transmitted in plaintext.

Now repeat with HTTPS. The network still sees endpoints and TLS metadata, but properly protected application content should not simply appear as readable HTTP data.

## Blue-team detection

Compare ARP tables over time.

A simple snapshot:

```bash
ip neigh > ~/lab/05_neigh_now.txt
```

Look for unexpected changes.

On a managed switch, study:

- DHCP snooping
- Dynamic ARP Inspection
- port security
- VLAN segmentation

## Better experiment: prove the defense

1. Run the attack.
2. Capture the ARP changes.
3. Enable the relevant protection.
4. Repeat.
5. Capture again.
6. Explain exactly what changed.

## Cleanup

Stop the spoofing processes:

```bash
sudo pkill arpspoof 2>/dev/null || true
```

Disable forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

Clear neighbor entries if needed:

```bash
sudo ip neigh flush all
```

Then revert the lab snapshot if the network is still confused.

## Important distinction

Passive sniffing, active MITM and TLS interception are different exercises.

Do not treat "I captured packets" as proof that you compromised the application. First prove you were in the path, then identify exactly what the protocol exposed.
