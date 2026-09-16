# 12 — Defensive Security: Detection Engineering, Hardening, and Attack Surface Reduction

## Concept first: defense is the inverse of the attack chain

A defender's job is not to memorize attack tools. It is to reduce exposure, detect anomalies, and prove the system is behaving as expected. The strongest defense is built by understanding the exact path an attacker would take and the indicators a system would generate.

### Offensive angle

Offense helps identify which services are exposed, which controls are weak, and what logs will be created during abuse. A skilled attacker is often an excellent source of detection ideas because they know what suspicious behavior looks like.

### Defensive angle

Defense is about segmentation, firewalling, key-based authentication, service minimization, logging, and validation. The important question is not simply "Is the firewall on?" but "What traffic is allowed, who controls it, and how would we know if it changed?"

### Commands explained

- `ufw status` and `ufw allow`: inspect and apply host-based firewall rules.
- `systemctl disable --now`: remove unnecessary services and shrink the attack surface.
- `journalctl`, `tail -f /var/log/auth.log`, and `grep -i "failed"`: reveal real authentication events and suspicious patterns.
- `ss -lntup` and `nmap -sV`: retest the system after hardening to confirm the change in exposure.

The defense objective is to make malicious behavior easier to detect and harder to execute, while preserving operational need.

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

## Start with exposure

On the server:

```bash
ss -lntup
```

From Kali:

```bash
nmap -sV <TARGET>
```

Write down the difference between:

```text
Needed service
Unneeded service
Needed but restricted service
Dangerous management service
```

## Host firewall

With UFW on a Debian/Ubuntu lab server:

```bash
sudo ufw status verbose
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

Do not copy firewall rules blindly. Replace them with the services your lab actually needs.

Check:

```bash
sudo ufw status numbered
```

For nftables:

```bash
sudo nft list ruleset
```

## Remove attack surface

List services:

```bash
systemctl --type=service --state=running
```

For a service you know is unnecessary:

```bash
sudo systemctl disable --now <service>
```

Retest:

```bash
ss -lntup
nmap -sV <TARGET>
```

## Logging

Useful sources:

```bash
journalctl --since "1 hour ago"
journalctl -p warning
journalctl -u ssh
```

On Debian/Ubuntu you may also inspect:

```bash
sudo tail -f /var/log/auth.log
sudo tail -f /var/log/syslog
```

Web logs commonly live under:

```text
/var/log/nginx/
 /var/log/apache2/
```

## SSH hardening

Study and implement:

- key-based authentication
- disabling unnecessary password login
- restricting allowed users
- rate limiting
- firewall restrictions
- logging

After each change, test from a second VM before closing your current session.

## Network segmentation

Build separate virtual networks for:

```text
Management
Servers
Clients
Untrusted/IoT
```

Then write explicit firewall rules between them.

Do not think "VLAN = security" by itself. The security comes from the traffic policy enforced between segments.

## Detection lab

Generate controlled events:

```text
Nmap scan
Failed SSH logins
DNS anomaly
ARP change
Small HTTP load spike
```

Then find evidence.

Useful commands:

```bash
grep -i "failed" /var/log/auth.log
journalctl -u ssh
ss -ant
ip neigh
```

## Simple log analysis

Count failed authentication entries:

```bash
grep -i "failed" /var/log/auth.log | wc -l
```

Extract common source addresses, adjusting for your distro's log format:

```bash
grep -i "failed" /var/log/auth.log | awk '{print $NF}' | sort | uniq -c | sort -nr
```

Do not assume `$NF` is the IP on every log format. Inspect a real line first.

## Incident response

When you detect something:

```text
Detect
↓
Validate
↓
Contain
↓
Preserve evidence
↓
Eradicate
↓
Recover
↓
Retest
↓
Improve
```

Do not destroy evidence before understanding what happened.

## Capstone blue-team test

Start from a clean snapshot.

1. Run a controlled scan.
2. Run one application attack.
3. Run one network attack.
4. Collect logs and PCAPs.
5. Build a timeline.
6. Identify indicators.
7. Add a defensive control.
8. Repeat the same attacks.
9. Show which evidence disappeared, changed, or became easier to detect.

That is the beginning of real SOC work.
