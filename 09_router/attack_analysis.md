# 09 — Router Security: Management Plane Abuse and Control-Path Analysis

## Concept first: routers have two planes, and only one is obvious

The data plane forwards traffic; the management plane configures the router. Many attacks focus on the management plane because if you control the router, you can silently change routes, DNS, traffic policy, or firewall behavior. This is why router security is a boundary-security problem.

### Offensive angle

The attacker identifies reachable management interfaces, checks for default credentials, outdated firmware, unnecessary services, and exposed admin access. In many home or lab environments, the critical risk is not the internet-facing route but the ability to reach the administrator interface from the wrong network.

### Defensive angle

The defender closes the management plane by restricting access, disabling unnecessary services, moving admin interfaces to a management VLAN, enforcing strong authentication, and validating firmware. Security is stronger when the router's administrative path is smaller and better controlled.

### Commands explained

- `nmap -p- 192.168.56.1` and `nmap -sV 192.168.56.1`: find reachable router interfaces and versions.
- `curl -I` and `curl -v`: inspect management web interfaces and their authentication behavior.
- `ssh -v`: test whether SSH is reachable and what negotiation details are exposed.
- `journalctl` and `ss -lntup`: check which services are active and whether the router is exposing more than it should.

The goal is not to "hack a router" for its own sake; it is to prove how much damage poor management-plane design can cause.

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

## Treat the router as a security boundary

A router usually has at least two important planes:

```text
Data plane      → forwards traffic
Management      → web/SSH/API configuration
```

Attackers often want the management plane because changing the router can affect everything behind it.

## Recon your router VM

```bash
ip route
nmap -p- 192.168.56.1
nmap -sV 192.168.56.1
```

Then check the management interface:

```bash
curl -I http://192.168.56.1/
curl -v http://192.168.56.1/
```

If SSH is enabled:

```bash
ssh -v admin@192.168.56.1
```

Use only lab credentials.

## What to audit

Check:

- management exposed on WAN
- default credentials
- outdated firmware
- unnecessary services
- UPnP
- weak TLS
- weak password policy
- unrestricted SSH
- poor logging
- IPv6 rules missing
- management interface on the user VLAN

## Configuration attack exercise

Create an intentionally bad OpenWrt lab snapshot.

Examples:

```text
WAN management: enabled
SSH: open broadly
Unused service: enabled
Weak test password
```

Scan it.

Then harden it.

Scan again.

Your objective is to make the attack surface visibly smaller.

## Authentication testing

For a test account you created yourself, study:

- rate limiting
- account lockout
- session expiration
- MFA if supported
- password complexity
- logging

Do not run credential attacks against real routers.

## Configuration backup

Before major changes, back up the lab router configuration.

Then make one change at a time and verify it.

This prevents the classic lab mistake of changing five settings and having no idea which one fixed the problem.

## Red-team scenario

You are given:

```text
Router IP
One normal client
One server
No router credentials
```

Your job is not automatically "get admin."

First answer:

1. What ports are reachable?
2. What management interfaces exist?
3. What version is running?
4. Is WAN management reachable?
5. Is there a known vulnerability?
6. Can you prove the issue safely?
7. What evidence would the router log?
8. What configuration change closes it?

## Blue-team retest

After hardening:

```bash
nmap -p- 192.168.56.1
nmap -sV 192.168.56.1
```

Compare the before/after attack surface.

The cleanest router is usually not the one with the most complicated firewall. It is the one exposing the fewest unnecessary services and separating management from ordinary clients.
