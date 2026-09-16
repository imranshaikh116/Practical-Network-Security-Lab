# 08 — DHCP Abuse: Rogue Servers, Lease Manipulation, and Layer-2 Trust Testing

## Concept first: DHCP is a network configuration system that can be abused

DHCP is a trusted automation mechanism. It gives clients their IP, gateway, DNS, and lease information, which means a rogue server can silently redirect traffic or poison a client's view of the network. This is why DHCP is considered a Layer-2 trust decision.

### Offensive angle

The attacker runs a rogue DHCP server that replies faster than the legitimate one. The victim accepts the rogue offer and begins sending traffic to the wrong gateway or DNS server. In a controlled lab, this is an effective way to understand the trust assumptions behind a network.

### Defensive angle

Defenders use DHCP snooping, trusted switch ports, port security, VLAN enforcement, and detection of unexpected DHCP servers. A network is more secure when the client can trust the network configuration it receives.

### Commands explained

- `tcpdump -nn -vv 'udp port 67 or udp port 68'`: capture DHCP Discover/Offer/Request/Ack traffic.
- `dhclient -v`: force a client to request a new lease.
- `ip addr`, `ip route`, `resolvectl status`: verify whether the client accepted the expected network configuration.
- `dnsmasq`: used in the lab to simulate a rogue DHCP server with controlled settings.

A DHCP attack is not about the protocol being broken; it is about the client trusting the first valid answer without enough verification.

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

## DORA

DHCP normally follows:

```text
Discover
Offer
Request
Acknowledge
```

Watch it happen:

```bash
sudo tcpdump -i any -nn -vv 'udp port 67 or udp port 68'
```

On a disposable client, renew its lease using the mechanism supported by its OS.

## Understand the important options

Among other fields, DHCP can tell a client:

- IP address
- subnet mask
- default gateway
- DNS server
- lease time

A rogue DHCP server becomes dangerous because it can hand out incorrect network parameters.

## Build the lab

Use a dedicated L2 network containing:

```text
Legitimate DHCP server
        |
     Switch/virtual switch
     /               \
Client             Rogue DHCP VM
```

Do not connect this network to your real LAN.

Use a tiny address pool so mistakes are easy to recover from.

## Observe the legitimate server

Capture:

```bash
sudo tcpdump -i eth0 -nn -vv 'udp port 67 or udp port 68'
```

Record:

```text
Client MAC
Offered IP
Gateway
DNS server
Lease time
Server identifier
```

## Rogue DHCP demonstration

Use a dedicated DHCP implementation such as dnsmasq on the rogue VM, configured only for the isolated lab interface.

Keep the pool tiny and the lab physically/logically isolated.

When the client requests a lease, compare the legitimate and rogue offers.

You are looking for differences in:

```text
IP
Gateway
DNS
Lease
Server identifier
```

## DHCP starvation concept

Starvation consumes the available address pool so legitimate clients cannot obtain leases.

You do not need to run an automated starvation tool to understand it.

Make a test pool of only a few addresses and use several disposable clients. Watch the pool become exhausted.

The security lesson is that the attack abuses a finite resource.

## Blue-team controls

Study:

- DHCP snooping
- trusted switch ports
- Dynamic ARP Inspection
- port security
- VLAN segmentation
- monitoring for unexpected DHCP servers

## Detection

On a client, compare:

```bash
resolvectl status
ip route
ip addr
```

If the gateway or DNS server unexpectedly changes after a DHCP renewal, investigate.

## Final exercise

Create a table:

```text
Normal DHCP:
Gateway:
DNS:
Lease:

Rogue DHCP:
Gateway:
DNS:
Lease:

What changed:
How detected:
How prevented:
How verified:
```

Then restore the clean snapshot.
