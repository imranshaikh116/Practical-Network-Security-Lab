# 04 — Router Trust Models: MAC Filtering, Identity Abuse, and Access Control Testing

## Concept first: MAC addresses are not strong identities

A router may trust a MAC address, IP source, or local interface list, but these identifiers are often user-controlled or easy to spoof in a local network. The lab demonstrates that a trust decision based only on local identity is weak unless paired with stronger authentication and segmentation.

### Offensive angle

The attacker learns how to change the local identity and observe whether the policy follows it. If a router allows a MAC or source range without robust identity checks, the access policy becomes a local configuration problem rather than a security boundary.

### Defensive angle

A defender should not rely on MAC filtering alone. Better controls include authenticated access, firmware review, VLAN separation, DHCP validation, and logging of network identity changes.

### Commands explained

- `ip link show` and `ip addr`: inspect the current interface identity.
- `ip link set dev eth0 address ...`: change the MAC address on a lab interface to test policy assumptions.
- `sudo dhclient -v`: request a fresh DHCP lease after changing identity.
- `tcpdump arp or udp port 67 or udp port 68`: capture the DHCP and ARP behavior behind the policy decision.

The important decision is not whether a filter can be bypassed; it is whether the system has layered controls beyond a weak identity signal.

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

## What a MAC filter can and cannot prove

A MAC address is useful for local network delivery. It is not a cryptographic identity.

If a router says:

```text
Allow  AA:BB:CC:DD:EE:FF
Deny everything else
```

the router is trusting something the client can change.

This module demonstrates that weakness only with your own router VM and a disposable client.

## Establish the policy

On the client:

```bash
ip -br link
ip addr
ip route
```

Record the original MAC:

```bash
ip link show eth0
```

On the router, create a test allow/deny policy for that exact lab client.

Verify that the policy behaves as expected.

## Change the test client's MAC

Only on the isolated interface:

```bash
sudo ip link set dev eth0 down
sudo ip link set dev eth0 address 02:11:22:33:44:55
sudo ip link set dev eth0 up
```

Verify:

```bash
ip link show eth0
```

If DHCP is used, request a fresh lease using the method supported by your distro:

```bash
sudo dhclient -v
```

or restart the network manager connection.

Now test access to the router and capture the exchange:

```bash
sudo tcpdump -i any -nn arp or udp port 67 or udp port 68
```

## What just happened?

The router's policy was tied to a changeable local identifier.

That does not mean every MAC filter is useless. It means you should understand what it is actually controlling.

## Other filter mistakes worth testing

Build a router VM with deliberately weak rules and test:

- IP allowlist only
- MAC allowlist only
- destination-port filtering
- management interface reachable from the wrong segment
- IPv4 rules that do not have equivalent IPv6 rules
- rules that permit traffic because of an overly broad source range

Use a simple test matrix:

```text
Source → Destination → Port → Expected → Actual
```

## Defender's view

A better design uses multiple controls:

- authenticated access
- VLAN/segment boundaries
- firewall rules
- 802.1X where appropriate
- WPA2/WPA3
- management-plane restrictions
- logging

## Blue-team exercise

After changing the MAC, inspect the router logs. Does the event show:

- original MAC?
- new MAC?
- DHCP lease?
- authentication identity?
- source IP?

If the router has no useful identity or audit trail, that is itself a finding.

## Cleanup

Restore the original MAC, or simply revert the VM snapshot.

Then verify the original policy works again.
