# 01 — Foundations: Pentest Workflow, Threat Modeling, and Adversary Thinking

## Concept first: what this module is really teaching

This module is not about memorizing commands. It is about learning how an attacker moves from an observation to a validated hypothesis. A useful security investigation always asks: what is exposed, what is being trusted, what is being logged, and what change closes the gap.

### Offensive angle

An attacker begins with scope, asset inventory, and service discovery. The goal is to identify reachable systems, understand what each service is meant to do, and look for trust assumptions that can be abused. The offensive skill is not just running a tool; it is reading the output and deciding which service is worth testing.

### Defensive angle

A defender wants the same data, but from a different direction: understand exposed services, reduce unnecessary attack surface, verify logging, and measure normal behavior before a change. This is how a blue team distinguishes intentional use from suspicious activity.

### Commands explained

- `ip -br addr` and `ip route`: identify the machine's network identity and path selection.
- `ss -lntup`: reveal listening sockets, ports, and process ownership.
- `nmap -sn` and `nmap -sV`: discover active hosts and gather service metadata without jumping immediately to exploitation.
- `tcpdump`: capture traffic so you can explain what happened on the wire.

The pattern to repeat across all modules is: observe → explain → test → defend → retest.

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

## What you are actually learning

A pentest is not "run Nmap and then Metasploit." The useful skill is moving from an observation to a hypothesis and then proving it.

A practical chain looks like this:

```text
Scope
  ↓
Asset discovery
  ↓
Service discovery
  ↓
Enumeration
  ↓
Vulnerability hypothesis
  ↓
Validation
  ↓
Controlled exploitation
  ↓
Impact proof
  ↓
Detection
  ↓
Remediation
  ↓
Retest
```

Red teams go one step further. They ask whether several small weaknesses can be combined into a realistic path to a valuable asset.

Blue teams do the same exercise from the other direction: "If someone followed this path, where would we notice them?"

## Build an asset inventory

On every VM record:

```bash
hostname
ip -br addr
ip route
ip neigh
ss -lntup
uname -a
cat /etc/os-release
```

Save the output:

```bash
mkdir -p ~/lab/01/{notes,evidence}
ip -br addr | tee ~/lab/01/evidence/ip.txt
ss -lntup | tee ~/lab/01/evidence/listening-services.txt
```

## Passive before active

Start with information the machine gives you without aggressive probing.

```bash
ip route
ip neigh
cat /etc/resolv.conf
cat /etc/hosts
cat /etc/services | less
```

Then move to active discovery against your lab:

```bash
nmap -sn 192.168.56.0/24
nmap -sV <TARGET>
```

The important habit is to read the output. If port 22 says OpenSSH and port 80 says nginx, don't immediately launch an exploit. Identify the versions, configuration and application first.

## Establish a baseline

Before an attack, capture normal behavior.

Target:

```bash
uptime
free -h
ss -s
journalctl --since "10 minutes ago"
```

Attacker:

```bash
ping -c 5 <TARGET>
curl -I http://<TARGET>/
```

Packet capture:

```bash
sudo tcpdump -i any -nn -w ~/lab/01/evidence/baseline.pcap host <TARGET>
```

Generate normal traffic, stop the capture, and inspect it.

## The first mini-assessment

Pretend you have been given only:

`192.168.56.20`

Do not look at the target's documentation.

1. Discover the host.
2. Enumerate ports.
3. Identify services.
4. Find versions.
5. Make a table of possible attack surfaces.
6. Choose one finding.
7. Prove it without causing damage.
8. Write a remediation.
9. Retest.

A good report says what you observed and how you proved it. It does not just say "Nmap found port 80."

## Evidence discipline

Keep commands and evidence together:

```bash
script ~/lab/01/evidence/session.txt
```

Run your work, then type:

```bash
exit
```

You now have a rough command transcript.

For screenshots or packet captures, use filenames that tell you what they contain:

```text
01_normal_dns.pcap
02_service_enum.txt
03_exploit_before_patch.txt
04_exploit_after_patch.txt
```

That habit becomes extremely useful when you start doing longer red-team exercises.
